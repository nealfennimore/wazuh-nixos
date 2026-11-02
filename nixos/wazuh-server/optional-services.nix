# Options for the optional manager daemons: e-mail (wazuh-maild, with
# <email_alerts> and the <reports> that wazuh-monitord mails) and syslog
# forwarding (wazuh-csyslogd).
#
# optional-services-config.nix writes their ossec.conf blocks.
# default.nix runs the units.
#
# database_output is not here. Wazuh 4.14.8 has no wazuh-dbd (src/os_dbd is
# gone), and ReadConfig logs "The 'database_output' configuration is
# deprecated and no longer supported. This configuration will be ignored."
# (src/config/config.c). An assertion refuses it, so that a host does not
# believe that its alerts reach a database.
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.services.wazuh-server;

  emailAlert = types.submodule {
    options = {
      to = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Recipients of the alerts that this entry selects.";
      };
      level = mkOption {
        type = types.nullOr (types.ints.between 0 16);
        default = null;
        description = "Minimum alert level.";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Rule groups. Empty means every group.";
      };
      ruleIds = mkOption {
        type = types.listOf types.ints.unsigned;
        default = [ ];
        description = "Rule IDs. Empty means every rule.";
      };
      eventLocation = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Alert location (an agent name, an address or a log file).";
      };
      format = mkOption {
        type = types.enum [
          "full"
          "sms"
        ];
        default = "full";
        description = "full for the whole alert, sms for a short text.";
      };
      doNotDelay = mkOption {
        type = types.bool;
        default = false;
        description = "Send each alert at once, not after the grouping delay.";
      };
      doNotGroup = mkOption {
        type = types.bool;
        default = false;
        description = "Send each alert in its own message.";
      };
    };
  };

  report = types.submodule {
    options = {
      title = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Subject of the report.";
      };
      emailTo = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Recipients of the report.";
      };
      group = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Rule group to report on.";
      };
      category = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Rule category to report on.";
      };
      rule = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Rule ID to report on.";
      };
      level = mkOption {
        type = types.nullOr (types.ints.between 0 16);
        default = null;
        description = "Minimum alert level to report on.";
      };
      location = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Alert location to report on.";
      };
      srcip = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Source address to report on.";
      };
      user = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "User name to report on.";
      };
      showLogs = mkOption {
        type = types.bool;
        default = false;
        description = "Include the logs in the report.";
      };
    };
  };

  syslogOutput = types.submodule {
    options = {
      server = mkOption {
        type = types.str;
        example = "192.168.1.3";
        description = "Address or host name of the syslog server.";
      };
      port = mkOption {
        type = types.port;
        default = 514;
        description = "UDP port of the syslog server.";
      };
      level = mkOption {
        type = types.nullOr (types.ints.between 0 16);
        default = null;
        description = "Minimum alert level to forward.";
      };
      group = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Rule group to forward. Separate several with |.";
      };
      ruleIds = mkOption {
        type = types.listOf types.ints.unsigned;
        default = [ ];
        description = "Rule IDs to forward. Empty means every rule.";
      };
      location = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Alert location to forward.";
      };
      useFqdn = mkOption {
        type = types.bool;
        default = false;
        description = "Send the full host name instead of the part before the first dot.";
      };
      format = mkOption {
        type = types.enum [
          "default"
          "cef"
          "splunk"
          "json"
        ];
        default = "default";
        description = "Message format.";
      };
    };
  };
in
{
  options.services.wazuh-server = {
    email = {
      enable = mkEnableOption "e-mail alerts through wazuh-maild";
      smtpServer = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "127.0.0.1";
        description = ''
          SMTP relay that wazuh-maild connects to on port 25. maild speaks
          plain SMTP: no authentication and no TLS
          (src/os_maild/sendmail.c). Use a local relay for anything else.
          Set this or sendmail, not both.
        '';
      };
      sendmail = mkOption {
        type = types.nullOr types.path;
        default = null;
        example = literalExpression ''"''${pkgs.msmtp}/bin/sendmail"'';
        description = ''
          sendmail-compatible program instead of an SMTP relay. maild runs
          the configured path with no arguments and writes the message to
          its standard input (src/os_maild/sendmail.c), so the module
          configures a wrapper that runs this program with -t -i. The unit
          has NoNewPrivileges, so a program that needs setuid or setgid,
          such as the Postfix sendmail, does not work. msmtp does.
        '';
      };
      from = mkOption {
        type = types.str;
        example = "wazuh@example.com";
        description = "Sender address.";
      };
      to = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Default recipients of alert e-mail.";
      };
      replyTo = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Reply-To address.";
      };
      heloServer = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Name that maild sends in HELO.";
      };
      maxPerHour = mkOption {
        type = types.ints.between 1 1024;
        default = 12;
        description = "Maximum number of messages per hour. The rest are queued into one message.";
      };
      idsName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Name in the message header that identifies this manager.";
      };
      logSource = mkOption {
        type = types.enum [
          "alerts.log"
          "alerts.json"
        ];
        default = "alerts.log";
        description = "Alert file that maild reads.";
      };
    };

    emailAlerts = mkOption {
      type = types.listOf emailAlert;
      default = [ ];
      description = "Extra recipients for selected alerts, one <email_alerts> block each. Needs email.enable.";
    };

    reports = mkOption {
      type = types.listOf report;
      default = [ ];
      description = ''
        Daily reports, one <reports> block each. wazuh-monitord builds them
        once a day and mails them with the email settings. Needs
        email.enable.
      '';
    };

    syslogOutput = mkOption {
      type = types.listOf syslogOutput;
      default = [ ];
      description = "Syslog servers that receive alerts, one <syslog_output> block each. A non-empty list runs wazuh-csyslogd.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.email.enable || ((cfg.email.smtpServer == null) != (cfg.email.sendmail == null));
        message = "services.wazuh-server.email: set exactly one of smtpServer and sendmail.";
      }
      {
        assertion = cfg.email.enable || (cfg.emailAlerts == [ ] && cfg.reports == [ ]);
        message = "services.wazuh-server: emailAlerts and reports need email.enable.";
      }
      {
        # src/config/config.c ignores the block with a deprecation warning.
        assertion = !(cfg.settings ? database_output) && !(hasInfix "<database_output" cfg.extraConfig);
        message = "services.wazuh-server: database_output was removed upstream. Wazuh 4.14.8 has no wazuh-dbd and ignores the block.";
      }
    ];
  };
}
