# Alert shipping from the native server to the indexer. Run it with:
#
#   nix build .#checks.x86_64-linux.server-indexer
#
# Two VMs. indexer runs nixos/wazuh-indexer through the fixture the indexer
# test uses (TLS from the test PKI, the admin user with a password file).
# server runs nixos/wazuh-server with services.wazuh-server.indexer
# pointing at it, so the setup unit writes the keystore and filebeat ships
# logs/alerts/alerts.json.
#
# The alert comes from a syslog line that the manager's logcollector reads
# from a file named in extraConfig: an sshd login for an invalid user, which
# fires rule 5710 (ruleset/rules/0095-sshd_rules.xml, level 5). The test
# then asks the indexer for a document with that rule id in
# wazuh-alerts-4.x-*. It also asserts the template, the ingest pipeline and
# the keystore, and that nothing failed. filebeat has its own credential, so
# the keystore is proved separately: the manager's indexer connector must
# create the vulnerability state index with it, and must fail to with a
# wrong manager password while filebeat keeps the right one.
{
  pkgs,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  indexerPassword = "Test-password-42!";
  testLog = "/var/log/wazuh-test.log";
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-indexer";

  nodes.indexer = {
    imports = [ fixture.module ];
    environment.systemPackages = [
      pkgs.curl
      pkgs.jq
    ];
  };

  nodes.server =
    { pkgs, ... }:
    {
      imports = [ wazuhServerModule ];

      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        api.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        indexer = {
          hosts = [ "https://indexer:9200" ];
          tls = {
            ca = pki.ca;
            certificate = pki.server.cert;
            key = pki.server.key;
          };
          usernameFile = "/run/secrets/wazuh-indexer-username";
          passwordFile = "/run/secrets/wazuh-indexer-password";
        };
        extraConfig = ''
          <localfile>
            <log_format>syslog</log_format>
            <location>${testLog}</location>
          </localfile>
        '';
      };

      # Root-only, like the files secret managers create. The setup unit and
      # the filebeat unit must read them through LoadCredential. The log
      # file exists before logcollector starts, so it is monitored at once.
      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-indexer-username 0400 root root - admin"
        "f /run/secrets/wazuh-indexer-password 0400 root root - ${indexerPassword}"
        "f ${testLog} 0644 root root -"
      ];

      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
      ];
    };

  testScript = ''
    import json

    start_all()

    curl = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:${indexerPassword}'"

    with subtest("the indexer is up with the security configuration applied"):
        indexer.wait_for_unit("wazuh-indexer.service")
        indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
        indexer.wait_until_succeeds(
            curl + " 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s'"
            + " | jq -e '.status == \"yellow\" or .status == \"green\"'",
            timeout=300,
        )

    server.wait_for_unit("multi-user.target")

    with subtest("the indexer block is enabled and the keystore holds the credentials"):
        server.succeed("test $(systemctl show -p Result --value wazuh-server-setup.service) = success")
        server.succeed("grep -A1 '<indexer>' /var/ossec/etc/ossec.conf | grep -q '<enabled>yes</enabled>'")
        server.succeed("grep -q '<host>https://indexer:9200</host>' /var/ossec/etc/ossec.conf")
        # RocksDB writes CURRENT and a MANIFEST on open; the files belong to
        # wazuh because wazuh-modulesd opens the store read-write.
        server.succeed("test -f /var/ossec/queue/keystore/CURRENT")
        server.succeed("test $(stat -c %U:%G /var/ossec/queue/keystore) = wazuh:wazuh")
        server.succeed("test -z \"$(find /var/ossec/queue/keystore ! -user wazuh)\"")
        server.succeed("test -z \"$(find /var/ossec/queue/keystore -perm /o=rwx)\"")
        # Neither the password nor the user name is stored in clear.
        server.fail("grep -rq '${indexerPassword}' /var/ossec/queue/keystore")

    with subtest("filebeat runs as its own user in the sandbox and connects"):
        server.wait_for_unit("wazuh-filebeat.service")
        server.succeed("test $(systemctl show -p User --value wazuh-filebeat.service) = wazuh-filebeat")
        server.succeed("test $(systemctl show -p ProtectSystem --value wazuh-filebeat.service) = strict")
        server.succeed("test $(systemctl show -p NoNewPrivileges --value wazuh-filebeat.service) = yes")
        server.succeed("test -z \"$(systemctl show -p CapabilityBoundingSet --value wazuh-filebeat.service)\"")
        server.wait_until_succeeds(
            "journalctl -u wazuh-filebeat.service | grep -q 'Connection to backoff(elasticsearch(https://indexer:9200)) established'",
            timeout=300,
        )
        # The generated filebeat.yml references the environment, and the
        # password is neither in it nor in the registry.
        server.succeed("grep -q 'INDEXER_PASSWORD' /nix/store/*-filebeat.yml")
        server.fail("grep -rq '${indexerPassword}' /nix/store/*-filebeat.yml /var/lib/wazuh-filebeat")

    with subtest("filebeat loaded the Wazuh template and the alerts pipeline"):
        indexer.wait_until_succeeds(
            curl + " https://indexer:9200/_template/wazuh"
            + " | jq -e '.wazuh.index_patterns | index(\"wazuh-alerts-4.x-*\") != null'",
            timeout=300,
        )
        indexer.wait_until_succeeds(
            curl + " 'https://indexer:9200/_ingest/pipeline/filebeat-*-wazuh-alerts-pipeline'"
            + " | jq -e 'keys | length >= 1'",
            timeout=300,
        )

    with subtest("an alert on the server reaches wazuh-alerts-4.x-*"):
        server.wait_for_unit("wazuh-logcollector.service")
        server.succeed(
            "echo 'Oct 30 05:00:00 server sshd[4242]: Invalid user shipping-test from 10.9.8.7 port 40000' >> ${testLog}"
        )
        server.wait_until_succeeds(
            "grep -q '\"id\":\"5710\"' /var/ossec/logs/alerts/alerts.json",
            timeout=300,
        )
        hit = json.loads(indexer.wait_until_succeeds(
            curl + " 'https://indexer:9200/wazuh-alerts-*/_search?q=rule.id:5710'"
            + " | jq -e 'select(.hits.total.value >= 1) | .hits.hits[0]'",
            timeout=600,
        ))
        assert hit["_index"].startswith("wazuh-alerts-4.x-"), hit["_index"]
        assert hit["_source"]["rule"]["id"] == "5710", hit["_source"]["rule"]
        assert hit["_source"]["data"]["srcip"] == "10.9.8.7", hit["_source"]["data"]
        assert hit["_source"]["agent"]["id"] == "000", hit["_source"]["agent"]

    with subtest("the manager's indexer connector authenticates with the keystore"):
        # filebeat ships alerts with its own credential, so the alert above
        # says nothing about the keystore. The vulnerability scanner in
        # wazuh-modulesd creates its state index through the indexer
        # connector, which reads the keystore
        # (src/shared_modules/indexer_connector/src/indexerConnector.cpp).
        connected = "IndexerConnector initialized successfully for index: wazuh-states-vulnerabilities"
        refused = "IndexerConnector initialization failed for index 'wazuh-states-vulnerabilities"
        states = curl + " 'https://indexer:9200/_cat/indices/wazuh-states-vulnerabilities-*?h=index'"
        server.wait_until_succeeds(f"grep -qF '{connected}' /var/ossec/logs/ossec.log", timeout=600)
        indexer.succeed(states + " | grep -q '^wazuh-states-vulnerabilities-'")
        server.fail("grep -q 'Could not open template file' /var/ossec/logs/ossec.log")

    with subtest("a wrong manager password is refused while filebeat keeps its own"):
        # The negative control for the subtest above. setup has no
        # RemainAfterExit, so every start of wazuh-modulesd runs it again
        # through Requires, and it rebuilds the keystore from the password
        # file. A keystore edited in place does not survive that start, so
        # the wrong password goes into the file. filebeat keeps running with
        # the password it loaded at its start.
        password_file = "/run/secrets/wazuh-indexer-password"
        server.succeed("systemctl stop wazuh-modulesd.service")
        indexer.succeed(curl + " -X DELETE 'https://indexer:9200/wazuh-states-vulnerabilities-*'")
        indexer.fail(states + " | grep -q .")
        server.succeed(f"cp -p {password_file} {password_file}.saved")
        server.succeed(f"printf '%s' Wrong-password-0 > {password_file}")
        mark = server.succeed("wc -l < /var/ossec/logs/ossec.log").strip()
        server.succeed("systemctl start wazuh-modulesd.service")
        server.wait_until_succeeds(f"tail -n +{int(mark) + 1} /var/ossec/logs/ossec.log | grep -qF \"{refused}\"", timeout=600)
        server.fail(f"tail -n +{int(mark) + 1} /var/ossec/logs/ossec.log | grep -qF '{connected}'")
        indexer.fail(states + " | grep -q .")
        server.succeed("systemctl is-active wazuh-filebeat.service")
        # Restore the file. The next start rebuilds the keystore with it.
        server.succeed("systemctl stop wazuh-modulesd.service")
        server.succeed(f"mv {password_file}.saved {password_file}")
        mark = server.succeed("wc -l < /var/ossec/logs/ossec.log").strip()
        server.succeed("systemctl start wazuh-modulesd.service")
        server.wait_until_succeeds(f"tail -n +{int(mark) + 1} /var/ossec/logs/ossec.log | grep -qF '{connected}'", timeout=600)
        indexer.succeed(states + " | grep -q '^wazuh-states-vulnerabilities-'")

    with subtest("nothing died"):
        server.succeed("test -z \"$(systemctl list-units --state=failed --no-legend 'wazuh-*')\"")
        server.fail("grep CRITICAL /var/ossec/logs/ossec.log")
        # The indexer connector logs this when the keystore is empty and it
        # falls back to admin:admin.
        server.fail("grep -q 'found in the keystore' /var/ossec/logs/ossec.log")
        indexer.succeed("test -z \"$(systemctl list-units --state=failed --no-legend 'wazuh-*')\"")
  '';
}
