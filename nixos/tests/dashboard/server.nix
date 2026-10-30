# The dashboard against the native server module, in three VMs:
#
#   nix build .#checks.x86_64-linux.dashboard-server
#
# checks.dashboard uses a fake manager API. This check replaces it with
# services.wazuh-server from nixos/wazuh-server. The API user wazuh-wui gets
# its password from a file through wazuh-api-users.service, and the dashboard
# reaches the API over TLS with the test CA. The check asserts that
# check-stored-api reports the real manager name. It also asserts that the
# API rejects the wrong CA and the upstream default password.
{
  pkgs,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ../indexer/fixture.nix { inherit pkgs pki; };
  dashboardPackage = pkgs.callPackage ../../../pkgs/wazuh-dashboard { };
  # Test values that satisfy the API password policy. They live in the store.
  apiPasswords = {
    wazuh = "Wazuh-Api-Test1";
    wazuh-wui = "Wui-Api-Test2";
  };
  managerUser = pkgs.writeText "test-manager-user" "wazuh-wui";
  managerPassword = pkgs.writeText "test-manager-password" apiPasswords.wazuh-wui;
in
pkgs.testers.runNixOSTest {
  name = "wazuh-dashboard-server";
  nodes = {
    indexer = { ... }: { imports = [ fixture.module ]; };
    server = { pkgs, ... }: {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;
      virtualisation.cores = 2;
      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        api.tls = { certificate = pki.server.cert; key = pki.server.key; };
        api.users = {
          wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
          wazuh-wui.passwordFile = "/run/secrets/wazuh-api-wui";
        };
        auth.passwordFile = "/run/secrets/wazuh-authd-pass";
      };
      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-authd-pass 0400 root root - test-enrollment-password"
        "f /run/secrets/wazuh-api-wazuh 0400 root root - ${apiPasswords.wazuh}"
        "f /run/secrets/wazuh-api-wui 0400 root root - ${apiPasswords.wazuh-wui}"
      ];
    };
    dashboard = { ... }: {
      imports = [ ../../wazuh-dashboard ];
      virtualisation.memorySize = 2048;
      environment.systemPackages = [ pkgs.curl pkgs.jq ];
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
          usernameFile = "${managerUser}";
          passwordFile = "${managerPassword}";
        } ];
      };
    };
  };
  testScript = ''
    start_all()
    server.wait_for_unit("wazuh-api-users.service", timeout=900)
    server.succeed("test $(systemctl show -p Result --value wazuh-api-users.service) = success")
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    dashboard.wait_for_unit("wazuh-dashboard.service")
    status = "curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' https://dashboard:5601/api/status | jq -e '.status.overall.state == \"green\"'"
    dashboard.wait_until_succeeds(status, timeout=600)

    with subtest("check-stored-api reaches the native server API"):
        check = "curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d '{\"id\":\"manager-0\"}' https://dashboard:5601/api/check-stored-api"
        dashboard.wait_until_succeeds(check + " | jq -e '.statusCode == 200 and .data.cluster_info.manager == \"server\"'", timeout=600)
        # The dashboard host must reach the API only with the test CA.
        dashboard.succeed("curl --fail --silent --cacert ${pki.ca} -u 'wazuh-wui:${apiPasswords.wazuh-wui}' -X POST https://server:55000/security/user/authenticate | jq -e '.data.token | length > 0'")
        dashboard.fail("curl --fail --silent --cacert ${pki.wrongCa} -u 'wazuh-wui:${apiPasswords.wazuh-wui}' -X POST https://server:55000/security/user/authenticate")
        dashboard.fail("curl --fail --silent --cacert ${pki.ca} -u 'wazuh-wui:wazuh-wui' -X POST https://server:55000/security/user/authenticate")
  '';
}
