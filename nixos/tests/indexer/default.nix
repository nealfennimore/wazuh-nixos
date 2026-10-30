{ pkgs }:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ./fixture.nix { inherit pkgs pki; };
in pkgs.testers.runNixOSTest {
  name = "wazuh-indexer";
  nodes.indexer = { lib, ... }: {
    imports = [ fixture.module ];
    # Specific LAN address, not wildcard: admin must still reach hostname
    # loopback, while clients can reach the explicitly selected interface.
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ { address = "192.168.1.10"; prefixLength = 24; } ];
    services.wazuh-indexer.listenAddress = lib.mkForce "192.168.1.10";
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
  };
  # A second isolated indexer exercises the production loopback defaults. The
  # test driver's generated LAN host mapping is replaced with NixOS's normal
  # local hostname mapping, so this specifically catches 127.0.0.1-only binds.
  nodes.indexer2 = { lib, ... }: {
    imports = [ (import ./fixture.nix { inherit pkgs pki; nodeName = "indexer2"; defaultListen = true; }).module ];
    networking.hosts = lib.mkForce {
      "127.0.0.2" = [ "indexer2" ];
      "127.0.0.1" = [ "localhost" ];
      "::1" = [ "localhost" ];
    };
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
  };
  testScript = ''
    start_all()
    indexer2.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    indexer2.succeed("curl --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' https://indexer2:9200")
    indexer2.succeed("curl --fail --silent --cacert ${pki.ca} --resolve indexer2:9200:127.0.0.1 -u 'admin:Test-password-42!' https://indexer2:9200")
    indexer.fail("curl --connect-timeout 3 --fail --silent --cacert ${pki.ca} -u 'admin:Test-password-42!' https://indexer2:9200")
    indexer.wait_for_unit("wazuh-indexer.service")
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
    indexer2.succeed("curl --fail --silent --cacert ${pki.ca} --resolve indexer:9200:192.168.1.10 -u 'admin:Test-password-42!' https://indexer:9200")
    base = "curl --fail --silent --show-error --cacert ${pki.ca} -u 'admin:Test-password-42!'"
    indexer.wait_until_succeeds(base + " 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=5s' | jq -e '.status == \"yellow\" or .status == \"green\"'")
    indexer.succeed(base + " -H 'Content-Type: application/json' -XPUT 'https://indexer:9200/nixos-test/_doc/1?refresh=true' -d '{\"message\":\"persistent\"}'")
    indexer.succeed("systemctl restart wazuh-indexer")
    indexer.wait_until_succeeds("systemctl is-active wazuh-indexer-security.service", timeout=900)
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
