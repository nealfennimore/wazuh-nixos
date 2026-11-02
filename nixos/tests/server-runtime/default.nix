# The server's runtime connections in two VMs. Run it with:
#
#   nix build .#checks.x86_64-linux.server-runtime
#
# Scope: remoted runs a secure listener and a syslog listener on 514/udp at
# the same time, and the firewall opens both. A syslog message from the
# sender becomes an alert, wazuh-integratord hands it to the Slack
# integration, and the webhook, a local HTTP receiver, gets the request at
# the secret URL. The secrets come from root-only files: the GitHub token is
# in the installed ossec.conf and not in the store, the integration secrets
# are in no ossec.conf, and kernel audit shows that no secret was an
# argument of a process. integrations.log, ossec.log and the journal hold
# the redaction marker and not the secret. A secret that the Wazuh XML
# reader would change stops the setup unit.
#
# It does not reach GitHub, VirusTotal or Slack: the VMs have no Internet.
{
  pkgs,
  wazuhServerModule,
}:
let
  hookPath = "/services/T0TEST4242/B0TEST4242/HookPathSecret0123";
  hookUrl = "http://127.0.0.1:8099${hookPath}";
  vtKey = "VirusTotalKeySecret0123456789";
  githubToken = "ghp_GithubTokenSecret0123456789";
  secrets = [
    hookUrl
    hookPath
    vtKey
    githubToken
  ];

  # Writes the path and the body of every POST to /var/lib/hook/requests.
  receiver = pkgs.writers.writePython3 "hook-receiver" { } ''
    from http.server import BaseHTTPRequestHandler, HTTPServer


    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            with open("/var/lib/hook/requests", "ab") as f:
                f.write(self.path.encode() + b" " + body + b"\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")


    HTTPServer(("127.0.0.1", 8099), Hook).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-runtime";
  globalTimeout = 2 * 3600;

  nodes.server =
    { pkgs, ... }:
    {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        # The archive shows whether a syslog message arrived at all.
        logAll = true;
        remote.listeners = [
          {
            connection = "secure";
            port = 1514;
            protocol = [ "tcp" ];
            queueSize = 131072;
          }
          {
            connection = "syslog";
            port = 514;
            protocol = [ "udp" ];
            allowedIps = [ "192.168.1.0/24" ];
          }
        ];
        integrations.slack = {
          hookUrlFile = "/run/secrets/wazuh-slack-hook";
          level = 3;
        };
        integrations.virustotal = {
          apiKeyFile = "/run/secrets/wazuh-virustotal-key";
          groups = [ "syscheck" ];
        };
        github = {
          apiAuth = [
            {
              orgName = "example-org";
              apiTokenFile = "/run/secrets/wazuh-github-token";
            }
          ];
        };
      };

      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-slack-hook 0400 root root - ${hookUrl}"
        "f /run/secrets/wazuh-virustotal-key 0400 root root - ${vtKey}"
        "f /run/secrets/wazuh-github-token 0400 root root - ${githubToken}"
        "d /var/lib/hook 0755 root root -"
      ];

      systemd.services.hook-receiver = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = receiver;
      };

      # Every execve by the wazuh user, with its arguments.
      security.audit = {
        enable = true;
        rules = [ "-a always,exit -F arch=b64 -S execve -F uid=wazuh -k wazuh-exec" ];
      };
      security.auditd.enable = true;
    };

  nodes.sender =
    { pkgs, ... }:
    {
      environment.systemPackages = [ pkgs.util-linux ];
    };

  testScript = ''
    import shlex

    secrets = ${builtins.toJSON secrets}

    start_all()
    server.wait_for_unit("multi-user.target")

    with subtest("remoted runs both listeners"):
        for unit in ["wazuh-remoted", "wazuh-analysisd", "wazuh-integratord", "wazuh-modulesd"]:
            server.wait_for_unit(f"{unit}.service")
        server.wait_until_succeeds("ss -Hltn 'sport = :1514' | grep -q LISTEN", timeout=120)
        server.wait_until_succeeds("ss -Hlun 'sport = :514' | grep -q :514", timeout=120)
        # One child per <remote> block, and no single main process.
        server.succeed("test $(pgrep -c -x wazuh-remoted) -eq 2")
        server.succeed("test $(systemctl show -p MainPID --value wazuh-remoted.service) -eq 0")
        server.succeed("iptables -S nixos-fw | grep -- '-p udp' | grep -q 'dport 514'")

    with subtest("a syslog message reaches the Slack webhook through integratord"):
        server.wait_for_unit("hook-receiver.service")
        sender.wait_for_unit("multi-user.target")
        # The test hosts file also maps server to an IPv6 address, and the
        # syslog listener binds IPv4. UDP gives no error for a port that no
        # one listens on, so the sender names the IPv4 address.
        server_ipv4 = sender.succeed("getent ahostsv4 server | head -n1 | cut -d' ' -f1").strip()
        # sshd login attempt with an unknown user: rule 5710, level 5. It is
        # sent until its alert reaches the receiver, because UDP gives no
        # delivery signal and other alerts can reach the webhook first.
        for _ in range(24):
            sender.succeed(
                f"logger --rfc3164 --udp -n {server_ipv4} -P 514 -t sshd --id=4242 "
                + shlex.quote("Failed password for invalid user admin from 192.168.1.77 port 4242 ssh2")
            )
            status, _ = server.execute("grep -F ${hookPath} /var/lib/hook/requests | grep -qE '57(10|16) _\\(Level'")
            if status == 0:
                break
            server.sleep(5)
        print(sender.succeed("getent ahosts server"))
        print(server.execute("iptables -L nixos-fw -v -n | grep 514; ss -uanp | grep 514; cat /var/lib/hook/requests; grep -h sshd /var/ossec/logs/archives/archives.log; grep -h -E 'syslog|remoted' /var/ossec/logs/ossec.log | tail -20")[1])
        server.succeed("grep -F ${hookPath} /var/lib/hook/requests | grep -qE '57(10|16) _\\(Level'")

    with subtest("secrets are where they belong and nowhere else"):
        # The GitHub token is in the installed ossec.conf, as wazuh-modulesd
        # reads it; the store copy holds the token placeholder.
        server.succeed("grep -qF ${githubToken} /var/ossec/etc/ossec.conf")
        server.succeed("grep -qF @WAZUH_SECRET_github-api_auth-0-api_token@ /nix/store/*-ossec.conf")
        for s in secrets:
            server.fail(f"grep -rqF -- {shlex.quote(s)} /nix/store/*-ossec.conf")
        # The integration secrets are not in ossec.conf at all, and their
        # files belong to root and the wazuh group.
        for s in ["${hookUrl}", "${vtKey}"]:
            server.fail(f"grep -qF -- {shlex.quote(s)} /var/ossec/etc/ossec.conf")
        server.succeed("test \"$(stat -c '%U:%G %a' /var/ossec/etc/secrets/integration-slack-hook_url)\" = 'root:wazuh 640'")
        server.succeed("test \"$(stat -c '%U:%G %a' /var/ossec/etc/secrets/integration-virustotal-api_key)\" = 'root:wazuh 640'")

    with subtest("no secret was an argument of a process run as wazuh"):
        server.wait_for_unit("auditd.service")
        server.succeed("runuser -u wazuh -- ${pkgs.coreutils}/bin/true Canary-Argv-Runtime7")
        server.wait_until_succeeds("ausearch -i -k wazuh-exec | grep -F Canary-Argv-Runtime7", timeout=60)
        # The integration ran: its token placeholder is in the audit log.
        server.succeed("ausearch -i -k wazuh-exec | grep -F @WAZUH_SECRET_integration-slack-hook_url@")
        for s in secrets:
            server.fail(f"ausearch -i -k wazuh-exec | grep -F -- {shlex.quote(s)}")

    with subtest("the integration log and the daemon logs hold the redaction marker"):
        server.succeed("grep -qF '[secret]' /var/ossec/logs/integrations.log")
        # A failing request: the receiver goes away, so requests raises with
        # the URL path, which integratord copies to ossec.log.
        server.succeed("systemctl stop hook-receiver.service")
        for _ in range(24):
            sender.succeed(
                f"logger --rfc3164 --udp -n {server_ipv4} -P 514 -t sshd --id=4243 "
                + shlex.quote("Failed password for invalid user root from 192.168.1.78 port 4243 ssh2")
            )
            status, _ = server.execute("grep -q 'Unable to run integration for slack' /var/ossec/logs/ossec.log")
            if status == 0:
                break
            server.sleep(5)
        server.succeed("grep -q 'Unable to run integration for slack' /var/ossec/logs/ossec.log")
        for s in secrets:
            server.fail(f"grep -rqF -- {shlex.quote(s)} /var/ossec/logs")
            server.fail(f"journalctl -b | grep -qF -- {shlex.quote(s)}")

    with subtest("a secret that the XML reader would change stops setup"):
        server.succeed("printf '%s\\n' 'ghp_bad<token' > /run/secrets/wazuh-github-token")
        server.fail("systemctl restart wazuh-server-setup.service")
        server.succeed("journalctl -u wazuh-server-setup.service | grep -q 'secret github-api_auth-0-api_token must be one line'")
        server.succeed("grep -qF ${githubToken} /var/ossec/etc/ossec.conf")
        # A bad integration secret leaves the installed secrets in place.
        server.succeed("printf '%s\\n' '${githubToken}' > /run/secrets/wazuh-github-token")
        server.succeed("printf '%s\\n' 'http://127.0.0.1:8099/bad path' > /run/secrets/wazuh-slack-hook")
        server.fail("systemctl restart wazuh-server-setup.service")
        server.succeed("journalctl -u wazuh-server-setup.service | grep -q 'secret integration-slack-hook_url must be one line'")
        server.succeed("grep -qxF ${hookUrl} /var/ossec/etc/secrets/integration-slack-hook_url")
        server.succeed("grep -qxF ${vtKey} /var/ossec/etc/secrets/integration-virustotal-api_key")
        server.succeed("grep -qF ${githubToken} /var/ossec/etc/ossec.conf")
        # No staging directory is left behind.
        server.fail("ls -d /var/ossec/.wazuh-server-setup.*")
  '';
}
