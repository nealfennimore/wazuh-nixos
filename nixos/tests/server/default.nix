# A headless NixOS VM test of the server module. Run it with:
#
#   nix build .#checks.x86_64-linux.server
#
# Scope: the module evaluates, activation builds /var/ossec, every daemon
# starts under the sandbox and stays up, the four that chroot really are
# chrooted, remoted and authd listen, the ruleset loads (wazuh-analysisd -t),
# wazuh-api-users.service sets the API passwords from root-only files, and
# the API answers an authenticated request over TLS with the test PKI and
# refuses the upstream default password, a wrong password and a wrong CA.
#
# It does not enroll an agent, ship an alert to an indexer, or run a
# response. Those are checks.server-enrollment, checks.server-indexer and
# later phases in PLANS/WAZUH_SERVER_NIXOS.md.
{
  pkgs,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
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
  # Policy-compliant replacements for the upstream defaults wazuh:wazuh and
  # wazuh-wui:wazuh-wui. Test values. They live in the store.
  apiPasswords = {
    wazuh = "Wazuh-Api-Test1";
    wazuh-wui = "Wui-Api-Test2";
  };
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server";

  nodes.server =
    { pkgs, ... }:
    {
      imports = [ wazuhServerModule ];

      # analysisd holds the compiled ruleset in memory and the API is a
      # Python process pool. The test default is too small for both.
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        api.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        api.users = {
          wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
          wazuh-wui.passwordFile = "/run/secrets/wazuh-api-wui";
        };
        auth.passwordFile = "/run/secrets/wazuh-authd-pass";
      };

      # Root-only, like the files secret managers create. The setup unit
      # and the api-users unit must read them through LoadCredential, not
      # directly.
      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-authd-pass 0400 root root - test-enrollment-password"
        "f /run/secrets/wazuh-api-wazuh 0400 root root - ${apiPasswords.wazuh}"
        "f /run/secrets/wazuh-api-wui 0400 root root - ${apiPasswords.wazuh-wui}"
      ];

      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
      ];
    };

  testScript = ''
    server.start()
    server.wait_for_unit("multi-user.target")

    with subtest("activation built the tree"):
        server.succeed("test $(systemctl show -p Result --value wazuh-server-setup.service) = success")
        server.succeed("test $(stat -c %U:%G /var/ossec) = root:wazuh")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/etc) = root:wazuh:1770")
        # Store links for what runs outside the chroot, real files for what
        # is read inside it.
        for tree in ["bin", "lib", "framework", "wodles", "api/scripts"]:
            target = server.succeed(f"readlink /var/ossec/{tree}").strip()
            assert target.startswith("/nix/store/"), f"{tree} -> {target}"
        for path in ["ruleset", "etc/internal_options.conf", "etc/ossec.conf", "etc/lists", "var/db/mitre.db"]:
            server.succeed(f"test ! -L /var/ossec/{path}")
        server.succeed("test -s /var/ossec/ruleset/rules/0010-rules_config.xml")
        server.succeed("grep -q '<port>1514</port>' /var/ossec/etc/ossec.conf")
        server.succeed("grep -q '<use_password>yes</use_password>' /var/ossec/etc/ossec.conf")
        server.succeed("grep -q '<enabled>no</enabled>' /var/ossec/etc/ossec.conf")
        # Active response on by default: the upstream command definitions,
        # no bound response, and the response programs linked under a
        # sticky directory that execd can lock in.
        server.succeed("grep -q '<name>firewall-drop</name>' /var/ossec/etc/ossec.conf")
        server.fail("grep -q '<name>restart-wazuh</name>' /var/ossec/etc/ossec.conf")
        server.fail("grep -q '<disabled>yes</disabled>' /var/ossec/etc/ossec.conf")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/active-response/bin) = root:wazuh:1770")
        target = server.succeed("readlink /var/ossec/active-response/bin/firewall-drop").strip()
        assert target.startswith("/nix/store/"), f"firewall-drop -> {target}"
        server.succeed("test ! -e /var/ossec/active-response/bin/restart-wazuh")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/etc/ossec.conf) = root:wazuh:640")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/etc/authd.pass) = wazuh:wazuh:640")
        server.succeed("grep -q test-enrollment-password /var/ossec/etc/authd.pass")
        server.succeed("test -s /var/ossec/etc/sslmanager.cert")
        server.succeed("test -s /var/ossec/etc/sslmanager.key")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/api/configuration/ssl/server.key) = wazuh:wazuh:600")
        server.succeed("test -f /var/ossec/etc/localtime")

    with subtest("every daemon is up, as wazuh, in the sandbox"):
        for unit in ${builtins.toJSON (chrootDaemons ++ otherDaemons)}:
            server.wait_for_unit(f"{unit}.service")
            server.succeed(f"test $(systemctl show -p User --value {unit}.service) = wazuh")
            server.succeed(f"test $(systemctl show -p ProtectSystem --value {unit}.service) = strict")
            server.succeed(f"test $(systemctl show -p NoNewPrivileges --value {unit}.service) = yes")

    with subtest("the four upstream chroots happened, and only those"):
        for unit in ${builtins.toJSON chrootDaemons}:
            pid = server.succeed(f"systemctl show -p MainPID --value {unit}.service").strip()
            root = server.succeed(f"readlink /proc/{pid}/root").strip()
            assert root == "/var/ossec", f"{unit}: root is {root}"
            server.succeed(f"test $(systemctl show -p CapabilityBoundingSet --value {unit}.service) = cap_sys_chroot")
        for unit in ${builtins.toJSON otherDaemons}:
            pid = server.succeed(f"systemctl show -p MainPID --value {unit}.service").strip()
            root = server.succeed(f"readlink /proc/{pid}/root").strip()
            assert root == "/", f"{unit}: root is {root}"
            server.succeed(f"test -z \"$(systemctl show -p CapabilityBoundingSet --value {unit}.service)\"")

    with subtest("remoted, authd and the API listen"):
        server.wait_for_open_port(1514)
        server.wait_for_open_port(1515)
        server.wait_for_open_port(55000)

    with subtest("the ruleset loads"):
        server.succeed("WAZUH_HOME=/var/ossec /var/ossec/bin/wazuh-analysisd -t")

    with subtest("the api-users unit set the passwords from root-only files"):
        # The unit waits for the API itself, so this is the API start time
        # plus the password changes. It fails fast if the unit fails.
        server.wait_for_unit("wazuh-api-users.service")
        server.succeed("test $(systemctl show -p Result --value wazuh-api-users.service) = success")
        server.succeed("test $(systemctl show -p User --value wazuh-api-users.service) = wazuh")
        server.succeed("journalctl -u wazuh-api-users.service | grep -q 'wazuh: password set'")
        server.succeed("journalctl -u wazuh-api-users.service | grep -q 'wazuh-wui: password set'")

    with subtest("the API authenticates with the test PKI and the new passwords"):
        base = "curl --fail --silent --show-error --cacert ${pki.ca}"
        auth = "-X POST 'https://server:55000/security/user/authenticate?raw=true'"
        token = server.succeed(base + " -u wazuh:${apiPasswords.wazuh} " + auth).strip()
        assert len(token) > 20, f"token: {token!r}"
        server.succeed(
            base + f" -H 'Authorization: Bearer {token}' https://server:55000/manager/info"
            + " | jq -e '.error == 0 and (.data.affected_items[0].version | startswith(\"v4.14\"))'"
        )
        server.succeed(base + " -u wazuh-wui:${apiPasswords.wazuh-wui} " + auth)
        # The upstream defaults are gone.
        server.fail(base + " -u wazuh:wazuh " + auth)
        server.fail(base + " -u wazuh-wui:wazuh-wui " + auth)
        server.fail(base + " -u wazuh:wrong " + auth)
        server.fail("curl --fail --silent --cacert ${pki.wrongCa} -u wazuh:${apiPasswords.wazuh} " + auth)
        server.fail(base + " https://server:55000/manager/info")

    with subtest("a second run of the api-users unit changes nothing and succeeds"):
        server.succeed("systemctl restart wazuh-api-users.service")
        server.succeed("test $(systemctl show -p Result --value wazuh-api-users.service) = success")
        server.succeed("journalctl -u wazuh-api-users.service | grep -q 'wazuh: the password is current'")
        server.succeed(base + " -u wazuh:${apiPasswords.wazuh} " + auth)

    with subtest("nothing died"):
        server.succeed("test -z \"$(systemctl list-units --state=failed --no-legend 'wazuh-*')\"")
        server.fail("grep CRITICAL /var/ossec/logs/ossec.log")

    with subtest("a second activation keeps host state and refreshes package files"):
        server.succeed("echo marker-keys >> /var/ossec/etc/client.keys")
        server.succeed("echo marker-local >> /var/ossec/etc/local_internal_options.conf")
        server.succeed("echo '<!-- marker-rule -->' >> /var/ossec/ruleset/rules/0010-rules_config.xml")
        cert = server.succeed("sha256sum /var/ossec/etc/sslmanager.cert").strip()
        server.succeed("systemctl restart wazuh-server-setup.service")
        server.succeed("grep -q marker-keys /var/ossec/etc/client.keys")
        server.succeed("grep -q marker-local /var/ossec/etc/local_internal_options.conf")
        server.fail("grep -q marker-rule /var/ossec/ruleset/rules/0010-rules_config.xml")
        assert cert == server.succeed("sha256sum /var/ossec/etc/sslmanager.cert").strip()
        for unit in ${builtins.toJSON (chrootDaemons ++ otherDaemons)}:
            server.succeed(f"systemctl is-active {unit}.service")
  '';
}
