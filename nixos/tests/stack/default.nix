# The full stack in four VMs: agent, server, indexer, dashboard. Run it with:
#
#   nix build .#checks.x86_64-linux.stack
#
# Scope: phase 6 of PLANS/WAZUH_SERVER_NIXOS.md. Every component check
# proves one seam. This test proves the chain: an event on the agent becomes
# an alert on the server, filebeat ships it to the indexer, and the dashboard
# reads the indexer and reaches the server API. The wiring of each node is
# copied from the check that proved it:
#
# - indexer: nixos/tests/indexer/fixture.nix, as is (checks.indexer).
# - server and agent: nixos/tests/server-enrollment (checks.server-enrollment),
#   plus api.users from nixos/tests/server (checks.server) and indexer from
#   nixos/tests/server-indexer (checks.server-indexer).
# - dashboard: nixos/tests/dashboard (checks.dashboard), with managers
#   pointing at the native API instead of the python fixture.
#
# Start order: indexer, then server, then agent and dashboard. The server
# starts when the indexer JVM is up, so the two long boots overlap. The
# agent and the dashboard start when remoted and authd listen, for the
# reason nixos/tests/server-enrollment gives: an agent that boots before the
# server fills the console with enrollment retries.
#
# Timeouts are sized for a shared builder. Measured there on 2026-10-30:
# the indexer takes 215 s to start and 395 s to security-ready, and the API
# took 350 s to listen with four VM tests on the builder. Four VMs here
# need about 9 GB: 3 GB indexer, 3 GB server, 2 GB dashboard, 1 GB agent.
{
  pkgs,
  wazuhModule,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  dashboardPackage = pkgs.callPackage ../../../pkgs/wazuh-dashboard { };

  # The fixture creates admin and kibanaserver with this password. The
  # server authenticates as admin, like checks.server-indexer; the dashboard
  # as kibanaserver, like checks.dashboard.
  indexerPassword = "Test-password-42!";

  # Enrollment password, as in checks.server-enrollment: a root-only file
  # on both nodes, read by PID 1 as a credential.
  enrollmentPasswordPath = "/run/secrets/wazuh-authd-pass";
  enrollmentPassword = "test-enrollment-password";
  enrollmentPasswordRule = "f ${enrollmentPasswordPath} 0400 root root - ${enrollmentPassword}";

  # Policy-compliant API passwords, the values checks.server uses. The
  # dashboard authenticates against the API as wazuh-wui, so its password
  # file holds the same value as the server's.
  apiPasswords = {
    wazuh = "Wazuh-Api-Test1";
    wazuh-wui = "Wui-Api-Test2";
  };
  # The dashboard module takes file paths as strings. Test values; they
  # live in the store.
  managerUserFile = pkgs.writeText "stack-manager-username" "wazuh-wui";
  managerPasswordFile = pkgs.writeText "stack-manager-password" apiPasswords.wazuh-wui;

  chrootDaemons = [
    "wazuh-db"
    "wazuh-analysisd"
    "wazuh-remoted"
    "wazuh-monitord"
  ];
  otherDaemons = [
    "wazuh-authd"
    "wazuh-syscheckd"
    "wazuh-logcollector"
    "wazuh-modulesd"
    "wazuh-execd"
    "wazuh-apid"
  ];
  agentDaemons = [
    "wazuh-agentd"
    "wazuh-logcollector"
    "wazuh-syscheckd"
    "wazuh-modulesd"
  ];
in
pkgs.testers.runNixOSTest {
  name = "wazuh-stack";

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
        auth.passwordFile = enrollmentPasswordPath;
        # The certificate the agent verifies (SAN DNS:server).
        auth.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        # The certificate the dashboard and curl verify.
        api.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        api.users = {
          wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
          wazuh-wui.passwordFile = "/run/secrets/wazuh-api-wui";
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
        # Every decoded event goes to logs/archives/archives.json, so the
        # archive probe below has something to find.
        logAll = true;
      };

      systemd.tmpfiles.rules = [
        enrollmentPasswordRule
        "f /run/secrets/wazuh-api-wazuh 0400 root root - ${apiPasswords.wazuh}"
        "f /run/secrets/wazuh-api-wui 0400 root root - ${apiPasswords.wazuh-wui}"
        "f /run/secrets/wazuh-indexer-username 0400 root root - admin"
        "f /run/secrets/wazuh-indexer-password 0400 root root - ${indexerPassword}"
      ];

      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
        pkgs.iproute2
      ];
    };

  nodes.agent =
    { ... }:
    {
      imports = [ wazuhModule ];

      services.wazuh-agent = {
        enable = true;
        # The hostname, because the server certificate names it. The server
        # listens on IPv6 for the reason given in nixos/tests/server-enrollment.
        manager.host = "server";
        manager.port = 1514;
        registration.port = 1515;
        registration.caFile = pki.ca;
        # A name that differs from the node hostname, so the server-side
        # check proves that -A reached authd.
        registration.agentName = "example-agent";
        registration.groups = [ "default" ];
        agentAuthPasswordFile = enrollmentPasswordPath;
      };

      systemd.tmpfiles.rules = [ enrollmentPasswordRule ];
    };

  nodes.dashboard =
    { ... }:
    {
      imports = [ ../../wazuh-dashboard ];
      virtualisation.memorySize = 2048;
      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
        pkgs.findutils
      ];
      services.wazuh-dashboard = {
        enable = true;
        package = dashboardPackage;
        listenAddress = "0.0.0.0";
        tls = {
          certificate = pki.dashboard.cert;
          key = pki.dashboard.key;
        };
        indexer = {
          hosts = [ "https://indexer:9200" ];
          ca = pki.ca;
          usernameFile = "${fixture.secrets}/kibanaserver";
          passwordFile = "${fixture.secrets}/password";
        };
        # The native API. ca joins the NODE_EXTRA_CA_CERTS bundle, which is
        # how the packaged client verifies the server certificate.
        managers = [
          {
            url = "https://server";
            port = 55000;
            usernameFile = "${managerUserFile}";
            passwordFile = "${managerPasswordFile}";
            ca = pki.ca;
            runAs = false;
          }
        ];
      };
    };

  testScript = ''
    import json
    import shlex

    indexer_curl = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:${indexerPassword}'"
    dashboard_curl = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:${indexerPassword}'"
    api_curl = "curl --fail --silent --show-error --cacert ${pki.ca}"
    api_auth = "-X POST 'https://server:55000/security/user/authenticate?raw=true'"


    def server_state():
        """What a failed enrollment, a missing event or a dead unit needs to be read."""
        for command in [
            "tail -n 60 /var/ossec/logs/ossec.log",
            "journalctl -u wazuh-authd -u wazuh-remoted -u wazuh-analysisd -u wazuh-apid -u wazuh-api-users --no-pager | tail -n 60",
            "journalctl -u wazuh-filebeat --no-pager | tail -n 40",
            "cat /var/ossec/etc/client.keys",
            "ss -Hltn",
            "systemctl list-units --no-legend 'wazuh-*'",
        ]:
            server.log(f"--- server: {command}")
            server.log(server.execute(command)[1])


    def agent_state():
        for command in [
            "journalctl -u wazuh-agent-auth -u wazuh-agentd --no-pager | tail -n 60",
            "cat /var/ossec/var/run/wazuh-agentd.state",
            "cat /var/ossec/etc/client.keys",
        ]:
            agent.log(f"--- agent: {command}")
            agent.log(agent.execute(command)[1])


    def dashboard_state():
        for command in [
            "journalctl -u wazuh-dashboard --no-pager | tail -n 60",
            "cat /var/lib/wazuh-dashboard/wazuh/config/wazuh.yml",
        ]:
            dashboard.log(f"--- dashboard: {command}")
            dashboard.log(dashboard.execute(command)[1])


    # Indexer first. The server starts once the JVM is up, so its boot
    # overlaps the security initialisation.
    indexer.start()
    indexer.wait_for_unit("wazuh-indexer.service", timeout=900)
    server.start()

    with subtest("the indexer is up with the security configuration applied"):
        # The fixture's wait, as in checks.indexer and checks.server-indexer.
        indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
        indexer.wait_until_succeeds(
            indexer_curl + " 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s'"
            + " | jq -e '.status == \"yellow\" or .status == \"green\"'",
            timeout=600,
        )
        indexer.fail("curl --fail --silent --cacert ${pki.wrongCa} -u 'admin:${indexerPassword}' https://indexer:9200")
        indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:admin https://indexer:9200")

    server.wait_for_unit("multi-user.target", timeout=900)

    with subtest("the server daemons are up and remoted and authd listen"):
        server.succeed("test $(systemctl show -p Result --value wazuh-server-setup.service) = success")
        for unit in ${builtins.toJSON (chrootDaemons ++ otherDaemons)}:
            server.wait_for_unit(f"{unit}.service", timeout=900)
            server.succeed(f"test $(systemctl show -p User --value {unit}.service) = wazuh")
            server.succeed(f"test $(systemctl show -p ProtectSystem --value {unit}.service) = strict")
        server.wait_for_open_port(1514, timeout=900)
        server.wait_for_open_port(1515, timeout=900)
        # A dual-stack socket shows as *:port. The agent resolves "server"
        # to its IPv6 address, so this decides whether it can connect.
        for port in [1514, 1515]:
            server.succeed(f"ss -Hltn 'sport = :{port}' | grep -q '\\*:{port} '")
        # The indexer block and the keystore, as checks.server-indexer asserts.
        server.succeed("grep -A1 '<indexer>' /var/ossec/etc/ossec.conf | grep -q '<enabled>yes</enabled>'")
        server.succeed("grep -q '<host>https://indexer:9200</host>' /var/ossec/etc/ossec.conf")
        server.succeed("test -f /var/ossec/queue/keystore/CURRENT")
        server.fail("grep -rq '${indexerPassword}' /var/ossec/queue/keystore")

    # Now the agent has authd to reach, and the dashboard has the indexer.
    # Both boot while the API comes up.
    agent.start()
    dashboard.start()

    with subtest("the API listens, has the new passwords, and authenticates"):
        try:
            server.wait_for_open_port(55000, timeout=900)
            # The unit waits for the API itself, then sets both passwords.
            server.wait_for_unit("wazuh-api-users.service", timeout=900)
            server.succeed("test $(systemctl show -p Result --value wazuh-api-users.service) = success")
            token = server.succeed(api_curl + " -u wazuh:${apiPasswords.wazuh} " + api_auth).strip()
            assert len(token) > 20, f"token: {token!r}"
            server.succeed(
                api_curl + f" -H 'Authorization: Bearer {token}' https://server:55000/manager/info"
                + " | jq -e '.error == 0 and (.data.affected_items[0].version | startswith(\"v4.14\"))'"
            )
            server.succeed(api_curl + " -u wazuh-wui:${apiPasswords.wazuh-wui} " + api_auth)
            server.fail(api_curl + " -u wazuh:wazuh " + api_auth)
            server.fail(api_curl + " -u wazuh-wui:wazuh-wui " + api_auth)
            server.fail("curl --fail --silent --cacert ${pki.wrongCa} -u wazuh:${apiPasswords.wazuh} " + api_auth)
        except Exception:
            server_state()
            raise

    agent.wait_for_unit("multi-user.target", timeout=900)
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=300)

    with subtest("the agent enrolls against authd and connects to remoted"):
        agent.succeed("grep -q '<address>server</address>' /var/ossec/etc/ossec.conf")
        agent.succeed("grep -q '<server_ca_path>${pki.ca}</server_ca_path>' /var/ossec/etc/ossec.conf")
        # A safety net, as in checks.server-enrollment: the server was
        # listening before the agent booted, so the boot attempt should
        # have worked. If it did not, no marker exists and this runs it.
        agent.succeed("systemctl restart wazuh-agent-auth.service")
        try:
            agent.wait_for_file("/var/ossec/var/.agent-registered", timeout=300)
            agent.succeed("test -s /var/ossec/etc/client.keys")
            server.wait_until_succeeds(
                "grep -q ' example-agent ' /var/ossec/etc/client.keys", timeout=300
            )
            # The daemons started before a key existed. Restart them by
            # name: restarting the target does not restart what it wants.
            for daemon in ${builtins.toJSON agentDaemons}:
                agent.succeed(f"systemctl restart {daemon}.service")
            agent.wait_until_succeeds(
                "journalctl -u wazuh-agentd | grep -q '(4102): Connected to the server'",
                timeout=600,
            )
            agent.wait_until_succeeds(
                "grep -q \"^status='connected'\" /var/ossec/var/run/wazuh-agentd.state",
                timeout=600,
            )
        except Exception:
            agent_state()
            server_state()
            raise

    with subtest("an event written on the agent reaches the server's archives.json"):
        # logcollector reads the journal with only-future-events, so the
        # probe is written after the daemons above came up.
        token = "wazuh-stack-archive-probe"
        agent.succeed(f"systemd-cat --identifier=wazuh-probe echo {token}")
        try:
            server.wait_until_succeeds(
                f"grep -q -F '{token}' /var/ossec/logs/archives/archives.json", timeout=600
            )
            server.succeed(
                f"grep -F '{token}' /var/ossec/logs/archives/archives.json"
                " | jq -e '.agent.name == \"example-agent\" and .location == \"journald\"'"
            )
        except Exception:
            agent_state()
            server_state()
            raise

    with subtest("an alert from the agent reaches wazuh-alerts-4.x-* on the indexer"):
        # The same probe as checks.server-enrollment: an identifier of sshd
        # reaches the sshd decoder, and "Failed password" matches rules
        # 5716 and 5760, level 5, above the alert level of 3.
        token = "wazuh-stack-alert-probe"
        agent.succeed(
            "systemd-cat --identifier=sshd"
            f" echo 'Failed password for {token} from 192.0.2.10 port 4242 ssh2'"
        )
        query = shlex.quote(json.dumps({
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.name": "example-agent"}},
                        {"match_phrase": {"full_log": token}},
                    ]
                }
            }
        }))
        try:
            server.wait_until_succeeds(
                f"grep -q -F '{token}' /var/ossec/logs/alerts/alerts.json", timeout=600
            )
            server.wait_for_unit("wazuh-filebeat.service", timeout=600)
            server.wait_until_succeeds(
                "journalctl -u wazuh-filebeat.service | grep -q 'Connection to backoff(elasticsearch(https://indexer:9200)) established'",
                timeout=600,
            )
            hit = json.loads(indexer.wait_until_succeeds(
                indexer_curl + " -H 'Content-Type: application/json'"
                + f" 'https://indexer:9200/wazuh-alerts-*/_search' -d {query}"
                + " | jq -e 'select(.hits.total.value >= 1) | .hits.hits[0]'",
                timeout=600,
            ))
            assert hit["_index"].startswith("wazuh-alerts-4.x-"), hit["_index"]
            assert hit["_source"]["agent"]["name"] == "example-agent", hit["_source"]["agent"]
            assert token in hit["_source"]["full_log"], hit["_source"]["full_log"]
            assert int(hit["_source"]["rule"]["level"]) >= 3, hit["_source"]["rule"]
        except Exception:
            server_state()
            raise

    with subtest("the dashboard status API answers with the indexer"):
        try:
            dashboard.wait_for_unit("wazuh-dashboard.service", timeout=900)
            dashboard.wait_for_open_port(5601, timeout=900)
            dashboard.wait_until_succeeds(
                dashboard_curl + " https://dashboard:5601/api/status"
                + " | jq -e '.status.overall.state == \"green\"'",
                timeout=600,
            )
            dashboard.fail("curl --fail --silent --cacert ${pki.wrongCa} https://dashboard:5601/api/status")
            dashboard.succeed("test $(stat -c %a /run/wazuh-dashboard/opensearch_dashboards.yml) = 600")
        except Exception:
            dashboard_state()
            raise

    with subtest("nothing died"):
        for machine in [indexer, server, agent, dashboard]:
            machine.succeed("test -z \"$(systemctl list-units --state=failed --no-legend 'wazuh-*')\"")
        server.fail("grep CRITICAL /var/ossec/logs/ossec.log")
        # The indexer connector logs this when the keystore is empty and it
        # falls back to admin:admin.
        server.fail("grep -q 'found in the keystore' /var/ossec/logs/ossec.log")
        for daemon in ${builtins.toJSON agentDaemons}:
            agent.fail(f"journalctl -u {daemon} | grep -q 'Bad system call'")
        agent.fail("journalctl -u wazuh-agentd -u wazuh-agent-auth | grep -q CRITICAL")

    # Last, and separable: the managers wiring against the native API has
    # not passed on its own yet (checks.dashboard proves it against a python
    # fixture). A failure here leaves every result above in the log.
    with subtest("the dashboard is configured for the server API and reaches it"):
        try:
            # What the module rendered from managers: configure.py writes
            # wazuh.yml as JSON, which is valid YAML.
            dashboard.succeed(
                "jq -e '.hosts[0][\"manager-0\"]"
                " | .url == \"https://server\" and .port == 55000"
                " and .username == \"wazuh-wui\" and .run_as == false'"
                " /var/lib/wazuh-dashboard/wazuh/config/wazuh.yml"
            )
            # The CA bundle the packaged client trusts is the test CA.
            dashboard.succeed("cmp -s /run/wazuh-dashboard/manager-ca.pem ${pki.ca}")
            # The packaged client refuses the native API without that CA.
            # The "success" variant of this probe expects the python
            # fixture's token, so only the two untrusted variants run here.
            client = dashboard.succeed(
                "find ${dashboardPackage}/share/wazuh-dashboard/plugins -path '*/server/services/server-api-client.js'"
            ).strip()
            probe = "${dashboardPackage}/share/wazuh-dashboard/node/bin/node ${../dashboard/manager-tls.cjs} " + client
            dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.wrongCa} " + probe + " untrusted")
            dashboard.succeed("env -u NODE_EXTRA_CA_CERTS " + probe + " untrusted")
            # The live check the dashboard exposes: it authenticates against
            # the stored manager-0 and asks the API for agent 000, whose
            # manager field is the server's host name.
            dashboard.wait_until_succeeds(
                dashboard_curl + " -H 'osd-xsrf: true' -H 'Content-Type: application/json'"
                + " -d '{\"id\":\"manager-0\"}' https://dashboard:5601/api/check-stored-api"
                + " | jq -e '.statusCode == 200 and .data.cluster_info.manager == \"server\""
                + " and (.data.apiIsDown // false) == false'",
                timeout=600,
            )
        except Exception:
            dashboard_state()
            server_state()
            raise
  '';
}
