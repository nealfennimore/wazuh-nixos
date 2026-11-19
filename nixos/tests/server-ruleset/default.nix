# Declared rules, decoders and CDB lists in one VM. Run it with:
#
#   nix build .#checks.x86_64-linux.server-ruleset
#
# Scope: services.wazuh-server.ruleset installs its files in
# etc/rules/declared, etc/decoders/declared and etc/lists/declared, where
# only root writes, and the running wazuh-analysisd uses them: an event
# written to the analysisd queue becomes
# an alert of a declared rule, through a declared decoder and a declared CDB
# list. A rule file whose name does not end in _rules.xml loads too. The API
# lists a declared rule and cannot write the declared directories. A rule
# file uploaded through the API goes to etc/rules and works after a restart
# of wazuh-analysisd. A second configuration removes one rule file and
# changes the list: the removed file leaves the host, its rule stops, the
# new list entry works, and the uploaded file stays.
#
# The test also records what PUT /manager/restart does to wazuh-analysisd.
# It prints the result and does not assert it.
{
  pkgs,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  apiPassword = "Wazuh-Api-Test1";

  # One datagram to the analysisd queue, as wazuh-logcollector sends it:
  # queue 1 (LOCALFILE_MQ), a location, then the log line.
  inject = pkgs.writers.writePython3Bin "wazuh-inject" { } ''
    import socket
    import sys

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect("/var/ossec/queue/sockets/queue")
    s.send(("1:ruleset-test:" + sys.argv[1]).encode())
  '';

  decoders = ''
    <decoder name="declared-app">
      <prematch>^declared-app: </prematch>
    </decoder>

    <decoder name="declared-app-user">
      <parent>declared-app</parent>
      <regex>user=(\S+)</regex>
      <order>dstuser</order>
    </decoder>
  '';

  rules = ''
    <group name="declared,">
      <rule id="100100" level="7">
        <decoded_as>declared-app</decoded_as>
        <description>Declared application event.</description>
      </rule>
      <rule id="100101" level="10">
        <if_sid>100100</if_sid>
        <list field="user" lookup="match_key">etc/lists/declared/blocked-users</list>
        <description>Declared application event of a blocked user.</description>
      </rule>
    </group>
  '';

  secondRules = ''
    <group name="declared,">
      <rule id="100110" level="6">
        <if_sid>100100</if_sid>
        <match>second-marker</match>
        <description>Declared application event with the second marker.</description>
      </rule>
    </group>
  '';

  # The name sorts after declared_rules.xml: analysisd loads the rule files of
  # all directories in file name order, and rule 100200 uses rule 100100.
  apiRules = pkgs.writeText "uploaded_rules.xml" ''
    <group name="uploaded,">
      <rule id="100200" level="8">
        <if_sid>100100</if_sid>
        <match>api-marker</match>
        <description>Declared application event with the API marker.</description>
      </rule>
    </group>
  '';
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-ruleset";
  globalTimeout = 2 * 3600;

  nodes.server =
    { pkgs, config, ... }:
    {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;
      system.switch.enable = true;

      services.wazuh-server = {
        enable = true;
        api.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        api.users.wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
        auth.passwordFile = "/run/secrets/wazuh-authd-pass";
        ruleset = {
          decoders."declared_decoders.xml".text = decoders;
          rules."declared_rules.xml".text = rules;
          # A name that does not end in _rules.xml. analysisd and the API
          # must both take it.
          # Absent from the second configuration: a specialisation has no
          # specialisations of its own.
          rules."second.xml" = pkgs.lib.mkIf (config.specialisation != { }) {
            source = pkgs.writeText "second.xml" secondRules;
          };
          lists."blocked-users".text = ''
            mallory:blocked
          '';
        };
      };

      specialisation.changed.configuration = {
        services.wazuh-server.ruleset = {
          lists."blocked-users".text = pkgs.lib.mkForce ''
            trudy:blocked
          '';
        };
      };

      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-authd-pass 0400 root root - test-enrollment-password"
        "f /run/secrets/wazuh-api-wazuh 0400 root root - ${apiPassword}"
      ];

      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
        inject
      ];
    };

  testScript = ''
    import json
    import shlex

    alerts = "/var/ossec/logs/alerts/alerts.json"


    def alert(token, rule):
        return f"grep -F {token} {alerts} | grep -qF '\"id\":\"{rule}\"'"


    def expect(message, token, rule):
        # analysisd opens its queue after it compiled the ruleset, and a
        # datagram to a queue that no one reads is lost. Send until the
        # alert is there.
        line = f"declared-app: {message} {token}"
        for _ in range(60):
            server.execute("wazuh-inject " + shlex.quote(line))
            if server.execute(alert(token, rule))[0] == 0:
                return
            server.sleep(5)
        print(server.execute(f"tail -n 3 {alerts}; grep wazuh-analysisd /var/ossec/logs/ossec.log | tail -n 30; ls -la /var/ossec/etc/rules/declared /var/ossec/etc/lists/declared")[1])
        raise Exception(f"no alert of rule {rule} for {line!r}")


    def started(unit):
        return server.succeed(f"systemctl show -p ActiveEnterTimestampMonotonic --value {unit}.service").strip()


    # The target waits for wazuh-api-users, which waits for the API. On a
    # loaded builder the API took from 385 s to more than 900 s to listen.
    server.wait_for_unit("wazuh-server.target", timeout=2400)
    server.wait_for_unit("wazuh-analysisd.service")

    with subtest("the declared files are installed and only root writes them"):
        etc = "/var/ossec/etc"
        for kind, mode in [("rules", "750"), ("decoders", "750"), ("lists", "1770")]:
            server.succeed(f"test \"$(stat -c '%U:%G %a' {etc}/{kind}/declared)\" = 'root:wazuh {mode}'")
            # The host directory above it stays with wazuh.
            server.succeed(f"test \"$(stat -c '%U:%G %a' {etc}/{kind})\" = 'wazuh:wazuh 770'")
        for path in [
            "rules/declared/declared_rules.xml",
            "rules/declared/second.xml",
            "decoders/declared/declared_decoders.xml",
            "lists/declared/blocked-users",
        ]:
            server.succeed(f"test \"$(stat -c '%U:%G %a' {etc}/{path})\" = 'root:wazuh 640'")
            server.succeed(f"test ! -L {etc}/{path}")
        # The package files of the host directories keep their owner.
        server.succeed(f"test \"$(stat -c '%U:%G %a' {etc}/rules/local_rules.xml)\" = 'wazuh:wazuh 660'")
        server.succeed("grep -q '<rule_dir>etc/rules/declared</rule_dir>' /var/ossec/etc/ossec.conf")
        server.succeed("grep -q '<decoder_dir>etc/decoders/declared</decoder_dir>' /var/ossec/etc/ossec.conf")
        server.succeed("grep -q '<list>etc/lists/declared/blocked-users</list>' /var/ossec/etc/ossec.conf")

    with subtest("the running analysisd uses the declared decoder, rules and list"):
        expect("login user=alice", "token-plain", "100100")
        expect("login user=mallory", "token-listed", "100101")
        expect("login user=alice second-marker", "token-second", "100110")
        # The list did its work: the plain event is not an alert of 100101.
        server.fail(alert("token-plain", "100101"))
        server.succeed(f"test -s {etc}/lists/declared/blocked-users.cdb")

    with subtest("the API lists a declared rule and cannot write the declared files"):
        server.wait_for_unit("wazuh-api-users.service")
        base = "curl --fail --silent --show-error --cacert ${pki.ca}"
        token = server.succeed(
            base + " -u wazuh:${apiPassword} -X POST 'https://server:55000/security/user/authenticate?raw=true'"
        ).strip()
        api = base + f" -H 'Authorization: Bearer {token}'"
        for rule_id, filename in [("100100", "declared_rules.xml"), ("100110", "second.xml")]:
            body = server.succeed(api + f" 'https://server:55000/rules?rule_ids={rule_id}'")
            print(f"GET /rules?rule_ids={rule_id}: {body}")
            items = json.loads(body)["data"]["affected_items"]
            assert len(items) == 1, f"rule {rule_id}: {len(items)} items"
            assert items[0]["filename"] == filename, items[0]["filename"]
            assert items[0]["relative_dirname"] == "etc/rules/declared", items[0]["relative_dirname"]
        body = server.succeed(api + " 'https://server:55000/decoders?decoder_names=declared-app'")
        print(f"GET /decoders?decoder_names=declared-app: {body}")
        items = json.loads(body)["data"]["affected_items"]
        assert len(items) >= 1, "the API does not list the declared decoder"
        assert items[0]["relative_dirname"] == "etc/decoders/declared", items[0]["relative_dirname"]
        body = server.succeed(api + " 'https://server:55000/lists/files?filename=blocked-users'")
        print(f"GET /lists/files?filename=blocked-users: {body}")
        items = json.loads(body)["data"]["affected_items"]
        assert len(items) == 1, "the API does not list the declared list"
        assert items[0]["relative_dirname"] == "etc/lists/declared", items[0]["relative_dirname"]
        apid = server.succeed("systemctl show -p MainPID --value wazuh-apid.service").strip()
        for kind in ["rules", "decoders", "lists"]:
            # Root in the mount namespace of the API: a read-only mount
            # refuses it, a mode bit does not.
            server.fail(f"nsenter -t {apid} -m -- touch {etc}/{kind}/declared/probe")
        # The control: the same probe succeeds where the API can write.
        server.succeed(f"nsenter -t {apid} -m -- touch /var/ossec/etc/rules/probe && rm /var/ossec/etc/rules/probe")

    with subtest("a rule file uploaded through the API works after a restart of analysisd"):
        server.succeed(
            api + " -X PUT -H 'Content-Type: application/octet-stream' --data-binary @${apiRules}"
            + " 'https://server:55000/rules/files/uploaded_rules.xml?overwrite=true' | jq -e '.error == 0'"
        )
        server.succeed("test \"$(stat -c '%U:%G' /var/ossec/etc/rules/uploaded_rules.xml)\" = 'wazuh:wazuh'")
        before = started("wazuh-analysisd")
        status, output = server.execute(api + " -X PUT 'https://server:55000/manager/restart'")
        server.sleep(60)
        after = started("wazuh-analysisd")
        print(f"MEASURED: PUT /manager/restart: exit {status}, body {output!r}, analysisd restarted: {before != after}")
        print("MEASURED: units: " + server.execute("systemctl list-units 'wazuh-*' --no-legend --plain")[1])
        print("MEASURED: log: " + server.execute("grep -i -E 'restart|execd' /var/ossec/logs/ossec.log /var/ossec/logs/api.log | tail -n 20")[1])
        server.succeed("systemctl restart wazuh-server.target")
        server.wait_for_unit("wazuh-analysisd.service")
        expect("login user=alice api-marker", "token-api", "100200")

    with subtest("a removed rule file leaves the host and a changed list is compiled again"):
        before = started("wazuh-analysisd")
        # A file that did not change keeps its inode.
        inode = server.succeed(f"stat -c %i {etc}/rules/declared/declared_rules.xml").strip()
        server.succeed("/run/current-system/specialisation/changed/bin/switch-to-configuration test >&2")
        server.wait_for_unit("wazuh-analysisd.service")
        assert started("wazuh-analysisd") != before, "analysisd did not restart for the new ruleset"
        server.succeed(f"test ! -e {etc}/rules/declared/second.xml")
        assert server.succeed(f"stat -c %i {etc}/rules/declared/declared_rules.xml").strip() == inode
        server.succeed(f"grep -q trudy {etc}/lists/declared/blocked-users")
        expect("login user=trudy", "token-trudy", "100101")
        # mallory left the list, and the second rule is gone. Each event is
        # an alert of the parent rule, so its arrival is known.
        expect("login user=mallory", "token-unlisted", "100100")
        server.fail(alert("token-unlisted", "100101"))
        expect("login user=alice second-marker", "token-removed", "100100")
        server.fail(alert("token-removed", "100110"))
        # The host-owned file of the API upload is not touched.
        expect("login user=alice api-marker", "token-kept", "100200")
  '';
}
