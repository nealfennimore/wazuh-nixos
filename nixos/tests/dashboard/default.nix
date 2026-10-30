{ pkgs }:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  dashboardPackage = pkgs.callPackage ../../../pkgs/wazuh-dashboard { };
  managerUser = pkgs.writeText "test-manager-user" "wazuh-wui";
in pkgs.testers.runNixOSTest {
  name = "wazuh-dashboard";
  nodes = {
    indexer = { lib, ... }: {
      imports = [ fixture.module ];
      environment.systemPackages = [ pkgs.curl ];
      # Mutable runtime hash, as with a secret manager, so the test can
      # rotate the kibanaserver password. Seeded once per boot.
      services.wazuh-indexer.users.kibanaserver.passwordHashFile = lib.mkForce "/run/secrets/kibanaserver-hash";
      system.activationScripts.kibanaserver-hash = ''
        [ -e /run/secrets/kibanaserver-hash ] || install -D -m400 ${fixture.secrets}/hash /run/secrets/kibanaserver-hash
      '';
    };
    server = { ... }: {
      networking.firewall.allowedTCPPorts = [ 55000 ];
      systemd.services.test-api = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python ${./api.py} ${pki.server.cert} ${pki.server.key}";
      };
    };
    dashboard = { ... }: {
      imports = [ ../../wazuh-dashboard ];
      virtualisation.memorySize = 2048;
      environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.findutils ];
      system.activationScripts.kibanaserver-password = ''
        [ -e /run/secrets/kibanaserver-password ] || install -D -m400 ${fixture.secrets}/password /run/secrets/kibanaserver-password
      '';
      services.wazuh-dashboard = {
        enable = true;
        package = dashboardPackage;
        listenAddress = "0.0.0.0";
        tls = { certificate = pki.dashboard.cert; key = pki.dashboard.key; };
        indexer = {
          hosts = [ "https://indexer:9200" ];
          ca = pki.ca;
          usernameFile = "${fixture.secrets}/kibanaserver";
          passwordFile = "/run/secrets/kibanaserver-password";
        };
        managers = [ {
          url = "https://server";
          ca = pki.ca;
          usernameFile = "${managerUser}";
          passwordFile = "${fixture.secrets}/password";
        } ];
      };
    };
  };
  testScript = ''
    import time
    start_all()
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    server.wait_for_unit("test-api.service")
    dashboard.wait_for_unit("wazuh-dashboard.service")
    dashboard.wait_for_open_port(5601)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d '{\"id\":\"manager-0\"}' https://dashboard:5601/api/check-stored-api | jq -e '.statusCode == 200 and .data.cluster_info.manager == \"server\"'", timeout=240)
    dashboard.fail("curl --fail --silent --cacert ${pki.wrongCa} https://dashboard:5601/api/status")
    dashboard.succeed("test $(stat -c %a /run/wazuh-dashboard/opensearch_dashboards.yml) = 600")
    dashboard.succeed("jq -e '.\"opensearch.requestTimeout\" == 120000' /run/wazuh-dashboard/opensearch_dashboards.yml")
    dashboard.fail("sudo -u nobody cat /run/wazuh-dashboard/opensearch_dashboards.yml")
    client = dashboard.succeed("find ${dashboardPackage}/share/wazuh-dashboard/plugins -path '*/server/services/server-api-client.js'").strip()
    node = "${dashboardPackage}/share/wazuh-dashboard/node/bin/node"
    probe = node + " ${./manager-tls.cjs} " + client
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.ca} " + probe + " success")
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.wrongCa} " + probe + " untrusted")
    dashboard.succeed("env -u NODE_EXTRA_CA_CERTS " + probe + " untrusted")
    dashboard.succeed("systemctl restart wazuh-dashboard")
    dashboard.wait_for_open_port(5601)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)

    with subtest("a rotated kibanaserver password reaches the dashboard on restart"):
        kibana = "curl --fail --silent --cacert ${pki.ca} -u 'kibanaserver:{}' https://indexer:9200"
        indexer.succeed("install -m400 ${fixture.rotated}/hash /run/secrets/kibanaserver-hash")
        indexer.succeed("systemctl restart wazuh-indexer-security.service")
        indexer.wait_until_succeeds(kibana.format("Rotated-password-43!"), timeout=120)
        indexer.fail(kibana.format("Test-password-42!"))

        # Stale credential. While it cannot authenticate, the dashboard never
        # becomes ready, and /api/status answers in plain text, not JSON.
        # Positive proof: the indexer logs a failed kibanaserver login from
        # the restarted process. Bounded negative: no 200 for a full minute.
        dashboard.succeed("systemctl restart wazuh-dashboard")
        dashboard.wait_for_open_port(5601)
        # Mark the time only now: before the restart, the old process also
        # held the stale password and its failures would match too.
        since = indexer.succeed("date '+%Y-%m-%d %H:%M:%S'").strip()
        indexer.wait_until_succeeds(f"journalctl -u wazuh-indexer --since '{since}' | grep -q 'Authentication finally failed for kibanaserver'", timeout=300)
        code = "curl --silent --output /dev/null --write-out '%{http_code}' --cacert ${pki.ca} -u 'admin:Test-password-42!' https://dashboard:5601/api/status"
        stale_codes = set()
        for _ in range(12):
            answer = dashboard.succeed(code).strip()
            stale_codes.add(answer)
            assert answer != "200", "dashboard status answered 200 with a stale kibanaserver password"
            time.sleep(5)
        print(f"status codes with the stale password: {sorted(stale_codes)}")

        dashboard.succeed("install -m400 ${fixture.rotated}/password /run/secrets/kibanaserver-password")
        dashboard.succeed("systemctl restart wazuh-dashboard")
        dashboard.succeed("jq -e '.\"opensearch.password\" == \"Rotated-password-43!\"' /run/wazuh-dashboard/opensearch_dashboards.yml")
        dashboard.wait_for_open_port(5601)
        # The old password no longer authenticates on the indexer, so green
        # means the dashboard connects with the new one.
        dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=600)
  '';
}
