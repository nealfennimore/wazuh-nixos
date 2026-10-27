{ pkgs }:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ./fixture.nix { inherit pkgs pki; };
in pkgs.testers.runNixOSTest {
  name = "wazuh-indexer";
  nodes.indexer = { ... }: {
    imports = [ fixture.module ];
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
  };
  testScript = ''
    start_all()
    indexer.wait_for_unit("wazuh-indexer.service")
    indexer.wait_for_unit("wazuh-indexer-security.service")
    base = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:Test-password-42!'"
    indexer.wait_until_succeeds(base + " 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s' | jq -e '.status == \"yellow\" or .status == \"green\"'")
    indexer.succeed(base + " -H 'Content-Type: application/json' -XPUT 'https://indexer:9200/nixos-test/_doc/1?refresh=true' -d '{\"message\":\"persistent\"}'")
    indexer.succeed("systemctl restart wazuh-indexer")
    indexer.wait_for_unit("wazuh-indexer-security.service")
    indexer.wait_until_succeeds(base + " https://indexer:9200/nixos-test/_doc/1 | jq -e '._source.message == \"persistent\"'")
    indexer.fail("curl --fail --silent --cacert ${pki.wrongCa} -u 'admin:Test-password-42!' https://indexer:9200")
    indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:wrong https://indexer:9200")
    indexer.fail("curl --fail --silent --cacert ${pki.ca} -u admin:admin https://indexer:9200")
    indexer.succeed("test $(stat -c %a /run/wazuh-indexer/node.key) = 600")
    indexer.fail("sudo -u nobody cat /run/wazuh-indexer/node.key")
    indexer.succeed("test $(systemctl show wazuh-indexer -p User --value) = wazuh-indexer")
    indexer.succeed("test $(systemctl show wazuh-indexer -p ProtectSystem --value) = strict")
  '';
}
