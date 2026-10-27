{ pkgs }:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  dashboardPackage = pkgs.callPackage ../../../pkgs/wazuh-dashboard { };
  managerUser = pkgs.writeText "test-manager-user" "wazuh-wui";
in pkgs.testers.runNixOSTest {
  name = "wazuh-dashboard";
  nodes = {
    indexer = { ... }: { imports = [ fixture.module ]; };
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
      services.wazuh-dashboard = {
        enable = true;
        package = dashboardPackage;
        listenAddress = "0.0.0.0";
        tls = { certificate = pki.dashboard.cert; key = pki.dashboard.key; };
        indexer = {
          hosts = [ "https://indexer:9200" ];
          ca = pki.ca;
          usernameFile = "${fixture.secrets}/kibanaserver";
          passwordFile = "${fixture.secrets}/password";
        };
        managers = [ {
          url = "https://server";
          ca = pki.ca;
          usernameFile = managerUser;
          passwordFile = "${fixture.secrets}/password";
        } ];
      };
    };
  };
  testScript = ''
    start_all()
    indexer.wait_for_unit("wazuh-indexer-security.service")
    server.wait_for_unit("test-api.service")
    dashboard.wait_for_unit("wazuh-dashboard.service")
    dashboard.wait_for_open_port(5601)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=240)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d '{\"id\":\"manager-0\"}' https://dashboard:5601/api/check-stored-api | jq -e '.statusCode == 200 and .data.cluster_info.manager == \"server\"'", timeout=240)
    dashboard.fail("curl --fail --silent --cacert ${pki.wrongCa} https://dashboard:5601/api/status")
    dashboard.succeed("test $(stat -c %a /run/wazuh-dashboard/opensearch_dashboards.yml) = 600")
    dashboard.fail("sudo -u nobody cat /run/wazuh-dashboard/opensearch_dashboards.yml")
    client = dashboard.succeed("find ${dashboardPackage}/share/wazuh-dashboard/plugins -path '*/server/services/server-api-client.js'").strip()
    node = "${dashboardPackage}/share/wazuh-dashboard/node/bin/node"
    probe = node + " ${./manager-tls.cjs} " + client
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.ca} " + probe + " success")
    dashboard.succeed("NODE_EXTRA_CA_CERTS=${pki.wrongCa} " + probe + " untrusted")
    dashboard.succeed("env -u NODE_EXTRA_CA_CERTS " + probe + " untrusted")
    dashboard.succeed("systemctl restart wazuh-dashboard")
    dashboard.wait_for_open_port(5601)
    dashboard.wait_until_succeeds("curl --fail --silent --cacert ${pki.ca} https://dashboard:5601/api/status -u 'admin:Test-password-42!' | jq -e '.status.overall.state == \"green\"'", timeout=240)
  '';
}
