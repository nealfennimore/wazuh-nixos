# A two node NixOS test: the agent module against the server module.
#
#   nix build .#checks.x86_64-linux.server-enrollment
#
# Scope: phase 3 of PLANS/WAZUH_SERVER_NIXOS.md. checks.enrollment proves the
# agent against the upstream container image. This test proves the same path
# against services.wazuh-server: the agent verifies authd with the test CA and
# enrolls, the server records the agent in its own client.keys, agentd
# connects to remoted, and an event written on the agent lands in the
# server's archives.json and, when a rule matches, in alerts.json.
#
# The agent names the server by hostname, not by address. The server
# certificate from nixos/tests/common/pki.nix carries SAN DNS:server, and
# the agent compares that name with the address it was given
# (os_auth/check_cert.c). runNixOSTest writes an A and an AAAA record for
# every node, and the agent takes the first getaddrinfo result
# (os_net.c, OS_GetHost), which is the IPv6 one. So the server must accept
# agents on IPv6, which is what services.wazuh-server.listenIPv6 does.
{
  pkgs,
  wazuhModule,
  wazuhServerModule,
}:
let
  pki = import ../common/pki.nix { inherit pkgs; };
  # Both nodes read the password from a root-only file, as a secret manager
  # would create it. Neither module reads the source directly: PID 1 passes
  # it to the setup unit as a credential.
  passwordPath = "/run/secrets/wazuh-authd-pass";
  password = "test-enrollment-password";
  passwordRule = "f ${passwordPath} 0400 root root - ${password}";

  agentDaemons = [
    "wazuh-agentd"
    "wazuh-logcollector"
    "wazuh-syscheckd"
    "wazuh-modulesd"
  ];
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-enrollment";

  nodes.server =
    { pkgs, ... }:
    {
      imports = [ wazuhServerModule ];

      # The same sizing as checks.server: analysisd holds the compiled
      # ruleset and the API is a Python process pool.
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        auth.passwordFile = passwordPath;
        # The certificate the agent verifies. Without auth.tls the module
        # generates a self-signed pair that names no host, and an agent
        # with registration.caFile set would refuse it.
        auth.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        api.tls = {
          certificate = pki.server.cert;
          key = pki.server.key;
        };
        # Every decoded event goes to logs/archives/archives.json, whether
        # or not a rule matches. Without it the archive probe below would be
        # discarded and prove nothing.
        logAll = true;
      };

      systemd.tmpfiles.rules = [ passwordRule ];

      environment.systemPackages = [
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

        # The hostname, because the server certificate names it. See the
        # header comment for why that needs the server to listen on IPv6.
        manager.host = "server";
        manager.port = 1514;
        registration.port = 1515;

        # Turns verification on for both enrollment paths: agent-auth gets
        # -v, and the <enrollment> block gets server_ca_path.
        registration.caFile = pki.ca;

        # A name that differs from the node hostname, so the server-side
        # check proves that -A reached authd. "default" is the one group
        # every manager has; authd rejects an enrollment that names a
        # missing group.
        registration.agentName = "example-agent";
        registration.groups = [ "default" ];

        agentAuthPasswordFile = passwordPath;
      };

      systemd.tmpfiles.rules = [ passwordRule ];
    };

  testScript = ''
    def server_state():
        """What a failed enrollment or a missing event needs to be read."""
        for command in [
            "tail -n 60 /var/ossec/logs/ossec.log",
            "journalctl -u wazuh-authd -u wazuh-remoted -u wazuh-analysisd --no-pager | tail -n 60",
            "cat /var/ossec/etc/client.keys",
            "ss -Hltn",
            "ls -l /var/ossec/logs/archives /var/ossec/logs/alerts",
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


    # The server starts alone, and the agent waits for its ports. Under
    # start_all() the agent would spend the server's startup retrying
    # enrollment and fill the console with "(1208): Unable to connect to
    # enrollment service", which buries whatever did go wrong.
    server.start()
    server.wait_for_unit("multi-user.target")

    with subtest("the server listens for enrollment and agent traffic"):
        server.wait_for_unit("wazuh-authd.service")
        server.wait_for_unit("wazuh-remoted.service")
        server.wait_for_open_port(1515)
        server.wait_for_open_port(1514)
        server.succeed("grep -q '<ipv6>yes</ipv6>' /var/ossec/etc/ossec.conf")
        # A dual-stack socket shows as *:port; an IPv4 one as 0.0.0.0:port.
        # The agent resolves "server" to its IPv6 address, so this is what
        # decides whether the enrollment below can connect at all.
        for port in [1514, 1515]:
            server.succeed(f"ss -Hltn 'sport = :{port}' | grep -q '\\*:{port} '")

    # Only now. The agent's own enrollment at boot then has something to
    # reach.
    agent.start()
    agent.wait_for_unit("multi-user.target")
    agent.wait_for_file("/var/ossec/etc/ossec.conf", timeout=120)

    with subtest("the agent configuration verifies the server"):
        agent.succeed("grep -q '<address>server</address>' /var/ossec/etc/ossec.conf")
        agent.succeed("grep -q '<server_ca_path>${pki.ca}</server_ca_path>' /var/ossec/etc/ossec.conf")
        agent.succeed("grep -q -- '-v ${pki.ca}' /etc/systemd/system/wazuh-agent-auth.service")
        agent.succeed("test $(stat -c %U:%G:%a /var/ossec/etc/authd.pass) = wazuh:wazuh:640")
        agent.wait_for_open_port(1515, "server")

    with subtest("the agent enrolls against authd"):
        # A safety net rather than the main path. The server was listening
        # before the agent booted, so the boot attempt should have worked.
        # If it did not, markRegistered wrote no marker, so
        # ConditionPathExists does not skip this attempt.
        agent.succeed("systemctl restart wazuh-agent-auth.service")
        try:
            agent.wait_for_file("/var/ossec/var/.agent-registered", timeout=180)
            agent.succeed("test -s /var/ossec/etc/client.keys")
            # The server's own copy is the independent evidence. authd appends
            # the agent under registration.agentName, not the node hostname,
            # which is what proves -A took effect.
            server.wait_until_succeeds(
                "grep -q ' example-agent ' /var/ossec/etc/client.keys", timeout=120
            )
            server.succeed("test $(stat -c %U:%G /var/ossec/etc/client.keys) = wazuh:wazuh")
        except Exception:
            agent_state()
            server_state()
            raise

    with subtest("the agent connects to remoted"):
        # The daemons started before a key existed. Restart them by name:
        # restarting the target does not restart what the target wants.
        for daemon in ${builtins.toJSON agentDaemons}:
            agent.succeed(f"systemctl restart {daemon}.service")
        try:
            agent.wait_until_succeeds(
                "journalctl -u wazuh-agentd | grep -q '(4102): Connected to the server'",
                timeout=240,
            )
            # agentd rewrites this file continuously. The status moves to
            # connected only when remoted answers, so it is server-side
            # evidence read from the agent.
            agent.wait_until_succeeds(
                "grep -q \"^status='connected'\" /var/ossec/var/run/wazuh-agentd.state",
                timeout=240,
            )
        except Exception:
            agent_state()
            server_state()
            raise

    with subtest("an event written on the agent reaches archives.json"):
        # logcollector reads the journal, and only-future-events defaults to
        # true, so the probe is written after the daemons above came up.
        token = "wazuh-server-enrollment-archive-probe"
        agent.succeed(f"systemd-cat --identifier=wazuh-probe echo {token}")
        try:
            server.wait_until_succeeds(
                f"grep -q -F '{token}' /var/ossec/logs/archives/archives.json", timeout=300
            )
            server.succeed(
                f"grep -F '{token}' /var/ossec/logs/archives/archives.json"
                " | jq -e '.agent.name == \"example-agent\" and .location == \"journald\"'"
            )
        except Exception:
            agent_state()
            server_state()
            raise

    with subtest("an event that matches a rule reaches alerts.json"):
        # The journald reader rebuilds a syslog line from SYSLOG_IDENTIFIER,
        # the PID and MESSAGE (logcollector/journal_log.c, entry_as_syslog),
        # so an identifier of sshd reaches the sshd decoder. The child
        # decoder ssh-failed (ruleset/decoders/0310-ssh_decoders.xml) takes
        # the line, so the alert names it with sshd as the parent. "Failed
        # password" matches rule 5716 and then 5760, both level 5, above
        # the alert level of 3.
        token = "wazuh-server-enrollment-alert-probe"
        agent.succeed(
            "systemd-cat --identifier=sshd"
            f" echo 'Failed password for {token} from 192.0.2.10 port 4242 ssh2'"
        )
        try:
            server.wait_until_succeeds(
                f"grep -q -F '{token}' /var/ossec/logs/alerts/alerts.json", timeout=300
            )
            server.succeed(
                f"grep -F '{token}' /var/ossec/logs/alerts/alerts.json"
                " | jq -e '.agent.name == \"example-agent\""
                " and (.decoder.parent // .decoder.name) == \"sshd\""
                " and (.rule.level | tonumber) >= 3'"
            )
        except Exception:
            server_state()
            raise

    with subtest("authd rejects an enrollment with a wrong password"):
        # The enrollments above supplied only the right password, so an
        # authd that ignored passwords would pass them too. agent-auth can
        # report a failure and still exit 0, so the evidence is on the
        # server: authd logs the refusal (os_auth/auth.c) and writes no key.
        mark = server.succeed("wc -l < /var/ossec/logs/ossec.log").strip()
        agent_auth = agent.succeed(
            "systemctl cat wazuh-agent-auth.service | grep -o '/nix/store/[^ ]*/bin/agent-auth' | head -n 1"
        ).strip()
        agent.execute(
            # The unit runs it from the home with WAZUH_HOME set.
            f"cd /var/ossec && WAZUH_HOME=/var/ossec {agent_auth} -m server -p 1515 -v ${pki.ca}"
            " -A wrong-password-agent -P not-the-password"
        )
        server.wait_until_succeeds(
            f"tail -n +{int(mark) + 1} /var/ossec/logs/ossec.log | grep -q 'Invalid password provided by'",
            timeout=60,
        )
        server.fail("grep -q ' wrong-password-agent ' /var/ossec/etc/client.keys")
        server.succeed("grep -q ' example-agent ' /var/ossec/etc/client.keys")

    with subtest("nothing died"):
        for machine in [server, agent]:
            machine.succeed("test -z \"$(systemctl list-units --state=failed --no-legend 'wazuh-*')\"")
        server.fail("grep CRITICAL /var/ossec/logs/ossec.log")
        for daemon in ${builtins.toJSON agentDaemons}:
            agent.fail(f"systemctl show -p Result --value {daemon}.service | grep -q signal")
            agent.fail(f"journalctl -u {daemon} | grep -q 'Bad system call'")
        agent.fail("journalctl -u wazuh-agentd -u wazuh-agent-auth | grep -q CRITICAL")
  '';
}
