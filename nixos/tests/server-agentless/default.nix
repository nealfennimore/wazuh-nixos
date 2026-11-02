# Agentless monitoring in two VMs. Run it with:
#
#   nix build .#checks.x86_64-linux.server-agentless
#
# Scope: wazuh-agentlessd on the server logs in to the target over SSH,
# once with a key and once with a password, both from root-only files. A
# periodic_diff check on each account raises rule 555 when the watched
# file changes. The password and the key are not in the Nix store, the
# password is not an argument of any process run as wazuh (kernel audit),
# and a host key that knownHosts does not list is refused.
{
  pkgs,
  wazuhServerModule,
}:
let
  password = "Agentless-Pw-4242";
  # Test keys, built once. They live in the store; a real host keeps them
  # outside it.
  keys = pkgs.runCommand "agentless-test-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C agentless -f $out/client
    ssh-keygen -q -t ed25519 -N "" -C target -f $out/host
  '';
  # A prompt that ends in "$", which the expect scripts wait for.
  profile = pkgs.writeText "profile" ''
    PS1='agentless$'
  '';
  check = user: file: {
    type = "ssh_generic_diff";
    hosts = [ "${user}@target" ];
    frequency = 20;
    state = "periodic_diff";
    arguments = "cat ${file}";
  };
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-agentless";
  globalTimeout = 2 * 3600;

  nodes.target =
    { pkgs, ... }:
    {
      services.openssh = {
        enable = true;
        settings.PasswordAuthentication = true;
        settings.KbdInteractiveAuthentication = true;
        hostKeys = [ ];
        extraConfig = "HostKey /etc/ssh/test_host_key";
      };
      environment.etc."ssh/test_host_key" = {
        source = "${keys}/host";
        mode = "0600";
      };
      users.users.monitor-key = {
        isNormalUser = true;
        shell = pkgs.dash;
        openssh.authorizedKeys.keyFiles = [ "${keys}/client.pub" ];
      };
      users.users.monitor-pw = {
        isNormalUser = true;
        shell = pkgs.dash;
        password = password;
      };
      systemd.tmpfiles.rules = [
        "L+ /home/monitor-key/.profile - - - - ${profile}"
        "L+ /home/monitor-pw/.profile - - - - ${profile}"
        "f /srv/watched-key 0644 root root - first"
        "f /srv/watched-pw 0644 root root - first"
      ];
    };

  nodes.server =
    { ... }:
    {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        agentless = {
          checks = [
            (check "monitor-key" "/srv/watched-key")
            (check "monitor-pw" "/srv/watched-pw")
          ];
          credentials = {
            "monitor-key@target" = { };
            "monitor-pw@target".passwordFile = "/run/secrets/agentless-pw";
          };
          sshKeyFile = "/run/secrets/agentless-key";
          knownHosts = "target ${builtins.readFile "${keys}/host.pub"}";
        };
      };

      systemd.tmpfiles.rules = [
        "f /run/secrets/agentless-pw 0400 root root - ${password}"
        "C /run/secrets/agentless-key 0400 root root - ${keys}/client"
      ];

      security.audit = {
        enable = true;
        rules = [ "-a always,exit -F arch=b64 -S execve -F uid=wazuh -k wazuh-exec" ];
      };
      security.auditd.enable = true;
    };

  testScript = ''
    start_all()
    target.wait_for_unit("sshd.service")
    server.wait_for_unit("multi-user.target")

    with subtest("agentlessd runs with the installed credentials"):
        server.wait_for_unit("wazuh-agentlessd.service")
        server.succeed("test \"$(stat -c '%U:%G %a' /var/ossec/.ssh/id_agentless)\" = 'wazuh:wazuh 600'")
        server.succeed("test \"$(stat -c '%U:%G %a' /var/ossec/agentless/.passlist)\" = 'root:wazuh 640'")
        server.succeed("test ! -L /var/ossec/agentless")
        server.succeed("base64 -d /var/ossec/agentless/.passlist | grep -qx 'monitor-key@target|NOPASS|'")
        server.succeed("base64 -d /var/ossec/agentless/.passlist | grep -qx 'monitor-pw@target|${password}|'")
        server.fail("grep -rqF -- '${password}' /nix/store/*-wazuh-server-setup /nix/store/*-ossec.conf")

    with subtest("a change on the target raises rule 555 for both accounts"):
        # The first run stores the output as the baseline.
        for user in ["monitor-key", "monitor-pw"]:
            server.wait_until_succeeds(f"test -s '/var/ossec/queue/diff/{user}@target->ssh_generic_diff/last-entry'", timeout=300)
        target.succeed("echo second > /srv/watched-key")
        target.succeed("echo second > /srv/watched-pw")
        # agentlessd writes diff.<time> when the output differs from the
        # baseline, and sends the diff to analysisd.
        for user in ["monitor-key", "monitor-pw"]:
            server.wait_until_succeeds(f"ls '/var/ossec/queue/diff/{user}@target->ssh_generic_diff/' | grep -q '^diff\\.'", timeout=300)
        # alerts.json carries the device as agentless.user and
        # agentless.host, with location wazuh-agentlessd.
        for user in ["monitor-key", "monitor-pw"]:
            server.wait_until_succeeds(
                "grep '\"id\":\"555\"' /var/ossec/logs/alerts/alerts.json"
                + f" | grep -F '\"agentless\":{{\"script\":\"ssh_generic_diff\",\"user\":\"{user}\",\"host\":\"target\"'",
                timeout=300,
            )

    with subtest("the password was never an argument of a process run as wazuh"):
        server.wait_for_unit("auditd.service")
        server.succeed("runuser -u wazuh -- ${pkgs.coreutils}/bin/true Canary-Agentless-7")
        server.wait_until_succeeds("ausearch -i -k wazuh-exec | grep -F Canary-Agentless-7", timeout=60)
        # The scripts ran: ssh to the target is in the audit log.
        server.succeed("ausearch -i -k wazuh-exec | grep -F 'monitor-pw@target'")
        server.fail("ausearch -i -k wazuh-exec | grep -F -- '${password}'")
        server.fail("journalctl -b | grep -F -- '${password}'")

    with subtest("a host key that knownHosts does not list is refused"):
        server.succeed("sed -i 's/^target /other /' /var/ossec/.ssh/known_hosts")
        server.fail("cd /var/ossec && runuser -u wazuh -- ${pkgs.openssh}/bin/ssh -o BatchMode=yes monitor-key@target true")
        # Setup restores the file from the configuration.
        server.succeed("systemctl restart wazuh-server-setup.service")
        server.succeed("cd /var/ossec && runuser -u wazuh -- ${pkgs.openssh}/bin/ssh -o BatchMode=yes monitor-key@target true")
  '';
}
