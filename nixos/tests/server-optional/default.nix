# The optional mail and syslog daemons in one VM. Run it with:
#
#   nix build .#checks.x86_64-linux.server-optional
#
# Scope: with email and syslogOutput set, wazuh-maild and wazuh-csyslogd
# run under the sandbox, maild in its chroot. An sshd log line read by
# logcollector becomes rule 5710, maild mails it to the <email_alerts>
# recipient through a local SMTP receiver, and csyslogd sends it as JSON to
# a local UDP receiver. Every daemon, monitord included, accepts the
# generated configuration with its <reports> block (-t).
#
# It does not wait for a daily report, which monitord sends after
# midnight, and it does not run the sendmail mode of maild.
{
  pkgs,
  wazuhServerModule,
}:
let
  smtpReceiver = pkgs.writers.writePython3 "smtp-receiver" {
    libraries = [ pkgs.python3Packages.aiosmtpd ];
  } ''
    import time

    from aiosmtpd.controller import Controller


    class Save:
        async def handle_DATA(self, server, session, envelope):
            with open("/var/lib/receivers/mail", "ab") as f:
                rcpt = ",".join(envelope.rcpt_tos).encode()
                f.write(b"RCPT " + rcpt + b"\n")
                f.write(envelope.content + b"\n.\n")
            return "250 OK"


    Controller(Save(), hostname="127.0.0.1", port=25).start()
    while True:
        time.sleep(3600)
  '';

  syslogReceiver = pkgs.writers.writePython3 "syslog-receiver" { } ''
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5514))
    while True:
        data, _ = s.recvfrom(65535)
        with open("/var/lib/receivers/syslog", "ab") as f:
            f.write(data + b"\n")
  '';

  receiver = name: exec: {
    wantedBy = [ "multi-user.target" ];
    before = [ "wazuh-server.target" ];
    serviceConfig = {
      ExecStart = exec;
      StateDirectory = "receivers";
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-optional";
  globalTimeout = 2 * 3600;

  nodes.server =
    { ... }:
    {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;

      services.wazuh-server = {
        enable = true;
        email = {
          enable = true;
          smtpServer = "127.0.0.1";
          from = "wazuh@example.com";
          to = [ "soc@example.com" ];
          maxPerHour = 100;
        };
        emailAlerts = [
          {
            to = [ "oncall@example.com" ];
            level = 5;
            doNotDelay = true;
            doNotGroup = true;
          }
        ];
        reports = [
          {
            title = "Daily authentication report";
            group = "authentication_failed";
            emailTo = [ "soc@example.com" ];
          }
        ];
        syslogOutput = [
          {
            server = "127.0.0.1";
            port = 5514;
            level = 5;
            format = "json";
          }
        ];
        settings = {
          alerts.email_alert_level = 5;
          # The default reader plus the test log.
          localfile = [
            {
              log_format = "syslog";
              location = "/var/ossec/logs/active-responses.log";
            }
            {
              log_format = "syslog";
              location = "/var/log/wazuh-test.log";
            }
          ];
        };
      };

      systemd.services.smtp-receiver = receiver "smtp" smtpReceiver;
      systemd.services.syslog-receiver = receiver "syslog" syslogReceiver;
    };

  testScript = ''
    server.wait_for_unit("multi-user.target")

    with subtest("maild and csyslogd run under the sandbox"):
        for unit in ["wazuh-maild", "wazuh-csyslogd", "wazuh-logcollector", "smtp-receiver", "syslog-receiver"]:
            server.wait_for_unit(f"{unit}.service")
        # maild chroots after it resolves the relay.
        server.wait_until_succeeds(
            "test \"$(readlink /proc/$(systemctl show -p MainPID --value wazuh-maild.service)/root)\" = /var/ossec",
            timeout=120,
        )

    with subtest("every daemon accepts the generated configuration"):
        for daemon in ["wazuh-analysisd", "wazuh-maild", "wazuh-csyslogd", "wazuh-monitord"]:
            server.succeed(f"cd /var/ossec && WAZUH_HOME=/var/ossec /var/ossec/bin/{daemon} -t")
        server.succeed("grep -q '<email_notification>yes</email_notification>' /var/ossec/etc/ossec.conf")
        server.succeed("grep -q '<reports>' /var/ossec/etc/ossec.conf")

    with subtest("an alert reaches the mail recipient and the syslog server"):
        # sshd login attempt with an unknown user: rule 5710, level 5. The
        # line is appended until both receivers have it, because
        # logcollector reads a new file from its end.
        for _ in range(36):
            server.succeed(
                "printf '%s server sshd[4242]: Failed password for invalid user admin from 192.168.1.77 port 4242 ssh2\\n'"
                + " \"$(date '+%b %e %H:%M:%S')\" >> /var/log/wazuh-test.log"
            )
            mail, _ = server.execute("grep -q 'RCPT .*oncall@example.com' /var/lib/receivers/mail && grep -q 5710 /var/lib/receivers/mail")
            syslog, _ = server.execute("grep -q '\"id\":\"5710\"' /var/lib/receivers/syslog")
            if mail == 0 and syslog == 0:
                break
            server.sleep(5)
        print(server.execute("cat /var/lib/receivers/mail; cat /var/lib/receivers/syslog; tail -n 30 /var/ossec/logs/ossec.log")[1])
        server.succeed("grep -q 'RCPT .*oncall@example.com' /var/lib/receivers/mail")
        server.succeed("grep -q 'From: .*wazuh@example.com' /var/lib/receivers/mail")
        server.succeed("grep -q '\"id\":\"5710\"' /var/lib/receivers/syslog")

    with subtest("nothing died"):
        for unit in ["wazuh-maild", "wazuh-csyslogd", "wazuh-analysisd", "wazuh-monitord"]:
            server.succeed(f"systemctl is-active {unit}.service")
  '';
}
