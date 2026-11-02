# Options for the server's runtime connections: the remoted listeners, the
# integrations that wazuh-integratord runs, and the GitHub audit-log module.
#
# runtime-config.nix writes their ossec.conf blocks. default.nix runs the
# units, opens the firewall and installs secrets in their runtime files.
#
# Secrets. Every *File option names a file that PID 1 reads through
# LoadCredential on the setup unit, so the file can be root-owned and stays
# out of the Nix store. The generated ossec.conf in the store holds a
# placeholder. Setup substitutes GitHub tokens in the runtime ossec.conf;
# integration secrets go into etc/secrets for the in-process wrapper.
# The Wazuh XML reader does not decode entities (src/os_xml/os_xml.c), so a
# secret is not escaped. The setup unit refuses a secret that the reader or
# integratord would change: see secretRule in default.nix.
{
  config,
  lib,
  options,
  ...
}:
with lib;
let
  cfg = config.services.wazuh-server;

  # The integrations that pkgs/wazuh-server installs under integrations/.
  # integratord runs integrations/<name> and disables an integration whose
  # file is absent (src/os_integrator/integrator.c, OS_IntegratorD).
  knownIntegrations = [
    "slack"
    "virustotal"
    "pagerduty"
    "shuffle"
    "maltiverse"
  ];

  listener = types.submodule {
    options = {
      connection = mkOption {
        type = types.enum [
          "secure"
          "syslog"
        ];
        description = "secure for agents, syslog for syslog senders.";
      };
      port = mkOption {
        type = types.port;
        description = "Port the listener binds.";
      };
      protocol = mkOption {
        type = types.nonEmptyListOf (
          types.enum [
            "tcp"
            "udp"
          ]
        );
        default = [ "tcp" ];
        description = "Transport protocols. Only a secure listener accepts both.";
      };
      localIp = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Address the listener binds. null binds every address.";
      };
      ipv6 = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = ''
          Bind an IPv6 socket. null follows services.wazuh-server.listenIPv6
          for a secure listener and binds IPv4 for a syslog listener: on a
          dual-stack socket an IPv4 sender arrives as an IPv4-mapped IPv6
          address, and allowedIps lists IPv4 networks.
        '';
      };
      allowedIps = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.168.1.0/24" ];
        description = ''
          Syslog senders that remoted accepts, as addresses or networks.
          remoted exits the syslog listener when the list is empty
          (src/remoted/remoted.c, HandleRemote), so a syslog listener needs
          at least one entry.
        '';
      };
      deniedIps = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Syslog senders that remoted refuses.";
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Size of the message queue of a secure listener. null keeps the Wazuh default.";
      };
    };
  };

  integration = types.submodule (
    { name, ... }:
    {
      options = {
        name = mkOption {
          type = types.enum knownIntegrations;
          default = name;
          defaultText = literalExpression "<name>";
          description = ''
            The integration program. The attribute name is the default, so
            two entries such as slack-critical and slack-auth can both set
            name = "slack".
          '';
        };
        hookUrl = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Webhook URL, written into the store. Use hookUrlFile for a URL that is a secret.";
        };
        hookUrlFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          example = "/run/secrets/wazuh-slack-hook";
          description = "File with the webhook URL, one line. Read by PID 1 through LoadCredential.";
        };
        apiKeyFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          example = "/run/secrets/wazuh-virustotal-key";
          description = "File with the API key, one line. Read by PID 1 through LoadCredential.";
        };
        level = mkOption {
          type = types.nullOr (types.ints.between 0 16);
          default = null;
          description = "Minimum alert level that the integration receives.";
        };
        ruleIds = mkOption {
          type = types.listOf types.ints.unsigned;
          default = [ ];
          description = "Rule IDs that the integration receives. Empty means every rule.";
        };
        groups = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "syscheck" ];
          description = "Rule groups that the integration receives. Empty means every group.";
        };
        eventLocation = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Regular expression for the alert location that the integration receives.";
        };
        alertFormat = mkOption {
          type = types.enum [ "json" ];
          default = "json";
          description = "Alert format. The packaged integrations read JSON only.";
        };
        maxLog = mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
          description = "Maximum length of the log text sent to the integration.";
        };
        options = mkOption {
          type = types.nullOr (types.attrsOf types.anything);
          default = null;
          description = "JSON object passed to the integration as its options file.";
        };
        timeout = mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
          description = "Seconds before the integration request times out.";
        };
        retries = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "Number of retries after a failed request.";
        };
      };
    }
  );

  apiAuth = types.submodule {
    options = {
      orgName = mkOption {
        type = types.str;
        description = "GitHub organization whose audit log is read.";
      };
      apiTokenFile = mkOption {
        type = types.path;
        example = "/run/secrets/wazuh-github-token";
        description = "File with a GitHub token that can read the audit log, one line. Read by PID 1 through LoadCredential. The installed token is readable by API users authorized to read the manager configuration.";
      };
    };
  };
in
{
  options.services.wazuh-server = {
    remote.listeners = mkOption {
      type = types.nonEmptyListOf listener;
      default = [
        {
          connection = "secure";
          port = cfg.remote.port;
          protocol = [ "tcp" ];
          queueSize = 131072;
        }
      ];
      defaultText = literalExpression ''
        [
          {
            connection = "secure";
            port = config.services.wazuh-server.remote.port;
            protocol = [ "tcp" ];
            queueSize = 131072;
          }
        ]
      '';
      example = literalExpression ''
        [
          { connection = "secure"; port = 1514; protocol = [ "tcp" ]; queueSize = 131072; }
          { connection = "syslog"; port = 514; protocol = [ "udp" ]; allowedIps = [ "192.168.1.0/24" ]; }
        ]
      '';
      description = ''
        The remoted listeners, one <remote> block each. remoted accepts at
        most one secure listener. A port below 1024 gives wazuh-remoted
        CAP_NET_BIND_SERVICE. Set either this option or remote.port, not
        both.
      '';
    };

    integrations = mkOption {
      type = types.attrsOf integration;
      default = { };
      example = literalExpression ''
        {
          virustotal = { apiKeyFile = "/run/secrets/wazuh-virustotal-key"; groups = [ "syscheck" ]; };
          slack = { hookUrlFile = "/run/secrets/wazuh-slack-hook"; level = 11; };
        }
      '';
      description = ''
        Integrations, one <integration> block each. A non-empty set runs
        wazuh-integratord. It passes placeholder tokens as arguments;
        the module's wrapper resolves file-backed secrets inside Python,
        keeping their values out of process arguments and redacting the
        upstream integration log and error output.
      '';
    };

    github = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            interval = mkOption {
              type = types.str;
              default = "1m";
              description = "Time between two audit-log reads.";
            };
            timeDelay = mkOption {
              type = types.str;
              default = "30s";
              description = "Delay that GitHub needs to publish an event to the audit log.";
            };
            curlMaxSize = mkOption {
              type = types.str;
              default = "1M";
              description = "Maximum size of one API response.";
            };
            onlyFutureEvents = mkOption {
              type = types.bool;
              default = true;
              description = "Read only events after the first start. false reads the existing log too.";
            };
            apiAuth = mkOption {
              type = types.nonEmptyListOf apiAuth;
              description = "Organizations and their tokens.";
            };
            eventType = mkOption {
              type = types.enum [
                "all"
                "git"
                "web"
              ];
              default = "all";
              description = "Audit-log event types to read.";
            };
          };
        }
      );
      default = null;
      description = "The GitHub audit-log module of wazuh-modulesd. null leaves it out.";
    };
  };

  config = mkIf cfg.enable {
    assertions =
      let
        secure = filter (l: l.connection == "secure") cfg.remote.listeners;
        ports = l: map (p: "${toString l.port}/${p}") l.protocol;
        allPorts = concatMap ports cfg.remote.listeners;
        remoteOpts = options.services.wazuh-server.remote;
      in
      [
        {
          # src/config/remote-config.c returns DUP_SECURE for a second one.
          assertion = length secure <= 1;
          message = "services.wazuh-server.remote.listeners: remoted accepts at most one secure listener.";
        }
        {
          assertion = all (l: l.connection == "secure" || length l.protocol == 1) cfg.remote.listeners;
          message = "services.wazuh-server.remote.listeners: only a secure listener can use tcp and udp together.";
        }
        {
          assertion = all (l: l.connection == "secure" || l.queueSize == null) cfg.remote.listeners;
          message = "services.wazuh-server.remote.listeners: queueSize applies to a secure listener only.";
        }
        {
          assertion = all (l: l.connection != "syslog" || l.allowedIps != [ ]) cfg.remote.listeners;
          message = "services.wazuh-server.remote.listeners: a syslog listener needs allowedIps, or remoted closes it.";
        }
        {
          assertion = length allPorts == length (unique allPorts);
          message = "services.wazuh-server.remote.listeners: two listeners use the same port and protocol.";
        }
        {
          # remote.port feeds only the default listener list. A host that
          # sets both would silently lose remote.port.
          assertion = !(remoteOpts.port.isDefined && remoteOpts.port.highestPrio < 1500 && remoteOpts.listeners.highestPrio < 1500);
          message = "services.wazuh-server: set remote.listeners or remote.port, not both.";
        }
      ]
      ++ mapAttrsToList (key: i: {
        # The key names the secret token, a credential and a file. integratord
        # splits its command line on spaces, so the token must not hold one.
        assertion = builtins.match "[A-Za-z0-9_-]+" key != null;
        message = "services.wazuh-server.integrations.${key}: use only letters, digits, - and _ in the name.";
      }) cfg.integrations
      ++ mapAttrsToList (key: i: {
        assertion = !(i.hookUrl != null && i.hookUrlFile != null);
        message = "services.wazuh-server.integrations.${key}: set hookUrl or hookUrlFile, not both.";
      }) cfg.integrations
      ++ mapAttrsToList (
        key: i:
        let
          # OS_IntegratorD in src/os_integrator/integrator.c disables an
          # integration that lacks what its program reads.
          needsHook = elem i.name [ "slack" "shuffle" "maltiverse" ];
          needsKey = elem i.name [ "virustotal" "pagerduty" "maltiverse" ];
          hasHook = i.hookUrl != null || i.hookUrlFile != null;
          hasKey = i.apiKeyFile != null;
        in
        {
          assertion = (needsHook -> hasHook) && (needsKey -> hasKey);
          message = "services.wazuh-server.integrations.${key}: ${i.name} needs ${
            concatStringsSep " and " (optional needsHook "hookUrl or hookUrlFile" ++ optional needsKey "apiKeyFile")
          }.";
        }
      ) cfg.integrations;
  };
}
