{ pkgs }:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  fixture = import ./fixture.nix { inherit pkgs pki; };
  inherit (fixture) rotated;
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
    # The admin hash lives in a mutable runtime file, as with a secret
    # manager, so the test can rotate it. Seeded once per boot.
    services.wazuh-indexer.users.admin.passwordHashFile = lib.mkForce "/run/secrets/indexer-admin-hash";
    system.activationScripts.indexer-admin-hash = ''
      [ -e /run/secrets/indexer-admin-hash ] || install -D -m400 ${fixture.secrets}/hash /run/secrets/indexer-admin-hash
    '';
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

    old = "Test-password-42!"
    new = "Rotated-password-43!"
    def admin(password):
        return f"curl --fail --silent --cacert ${pki.ca} -u 'admin:{password}' https://indexer2:9200"
    security = "wazuh-indexer-security.service"

    with subtest("a rotated hash file takes effect when the security unit reruns"):
        indexer2.succeed("install -m400 ${rotated}/hash /run/secrets/indexer-admin-hash")
        indexer2.succeed(f"systemctl restart {security}")
        indexer2.wait_until_succeeds(admin(new), timeout=120)
        indexer2.fail(admin(old))

    with subtest("an invalid hash fails the unit and leaves the active users alone"):
        indexer2.succeed("printf not-a-bcrypt-hash > /run/secrets/indexer-admin-hash")
        indexer2.fail(f"systemctl restart {security}")
        indexer2.succeed(f"journalctl -u {security} | grep -q 'Invalid bcrypt credential for indexer user'")
        # Neither the bad value nor the active hash reaches the journal.
        indexer2.fail(f"journalctl -u {security} | grep -q -F not-a-bcrypt-hash")
        indexer2.fail(f"journalctl -u {security} | grep -q -F \"$(cat ${rotated}/hash)\"")
        indexer2.succeed(admin(new))
        indexer2.fail(admin(old))

    with subtest("a valid hash file recovers through Restart=on-failure, without a manual start"):
        indexer2.succeed("install -m400 ${fixture.secrets}/hash /run/secrets/indexer-admin-hash")
        indexer2.wait_until_succeeds(f"systemctl is-active {security}", timeout=900)
        indexer2.succeed(f"test $(systemctl show -p NRestarts --value {security}) -gt 0")
        indexer2.wait_until_succeeds(admin(old), timeout=120)
        indexer2.fail(admin(new))
  '';
}
