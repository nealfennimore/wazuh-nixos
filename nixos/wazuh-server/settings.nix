{ config, lib, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.services.wazuh-server;
  # Keep service-owned sections out of the generic tree. In particular, no
  # token/credential can accidentally override the runtime-secret renderer.
  sections = [
    "global"
    "alerts"
    "logging"
    "rootcheck"
    "syscheck"
    "sca"
    "wodle"
    "localfile"
    "ruleset"
    "rule_test"
    "command"
    "active-response"
    "vulnerability-detection"
    "cluster"
    "labels"
    "agent-upgrade"
    "fluent-forward"
    "ms-graph"
    "office365"
    "socket"
    "task-manager"
    "wdb"
    "gcp-pubsub"
    "gcp-bucket"
  ];
  enabled = value: value == true || value == "yes";
in
{
  options.services.wazuh-server.settings = mkOption {
    type = import ./settings-type.nix { inherit lib; };
    default = { };
    description = ''
      Structured ossec.conf sections, merged recursively over generated
      defaults. Keys use upstream XML names; lists repeat an element and
      replace its default list. null omits an element. Booleans render as
      yes/no. Use _attributes for XML attributes and _text for element text.
      Managed remote, auth, indexer, integration and github sections use
      their dedicated options instead. Values are public Nix-store data:
      use the dedicated runtime secret-file options for credentials.
      This validates XML representation, not every upstream option schema.
    '';
    example = {
      global.agents_disconnection_time = "10m";
      syscheck.directories = [
        "/etc"
        "/run/current-system/sw/bin"
      ];
      syscheck.auto_ignore = {
        _attributes = {
          frequency = 10;
          timeframe = 3600;
        };
        _text = false;
      };
    };
  };
  options.services.wazuh-server.secretFiles = mkOption {
    type = types.attrsOf types.path;
    default = { };
    description = ''Runtime files referenced as { _secret = "name"; } in settings or auth.settings. Contents are inserted in the installed ossec.conf only. Use runtime string paths; API principals authorized to read manager configuration can read these values.'';
  };
  options.services.wazuh-server.credentialFiles = mkOption {
    type = types.attrsOf types.path;
    default = { };
    description = ''Files copied byte-for-byte at startup to /var/ossec/etc/credentials/<name>. Use { _credential = "name"; } in structured settings to render the installed path. Suitable for JSON service accounts and AWS profile files; contents never enter generated XML.'';
  };
  options.services.wazuh-server.auth.settings = mkOption {
    type = import ./settings-type.nix { inherit lib; };
    default = { };
    description = "Additional upstream auth settings, merged over defaults. Service enablement, port, password and TLS file paths use their dedicated options.";
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (name: builtins.match "[A-Za-z0-9_-]+" name != null) (
          builtins.attrNames cfg.secretFiles ++ builtins.attrNames cfg.credentialFiles
        );
        message = "services.wazuh-server secretFiles and credentialFiles names may contain only letters, digits, underscore and hyphen.";
      }
      {
        assertion = lib.all (name: !(builtins.hasAttr name cfg.auth.settings)) [
          "disabled"
          "port"
          "use_password"
          "ssl_agent_ca"
          "ssl_manager_cert"
          "ssl_manager_key"
        ];
        message = "Use services.wazuh-server.auth dedicated enable/port/passwordFile/agentCa/tls options for service-owned fields.";
      }
      {
        assertion = lib.all (section: builtins.elem section sections) (builtins.attrNames cfg.settings);
        message = "services.wazuh-server.settings supports only: ${lib.concatStringsSep ", " sections}. Use dedicated options for managed sections.";
      }
      {
        assertion = !(enabled (cfg.settings.global.email_notification or false));
        message = "Use services.wazuh-server.email.enable to run maild; raw settings.global.email_notification must remain disabled.";
      }
      {
        assertion =
          !(cfg.settings ? cluster)
          || cfg.settings.cluster == null
          || enabled (cfg.settings.cluster.disabled or false);
        message = "Use services.wazuh-server.cluster for clustering; raw settings.cluster must have disabled = true.";
      }
      {
        assertion = !(cfg.settings ? active-response) || cfg.activeResponse.enable;
        message = "services.wazuh-server.settings.active-response requires activeResponse.enable; use that option to disable responses.";
      }
      {
        assertion =
          !(enabled (cfg.settings.vulnerability-detection.enabled or false))
          || (cfg.indexer != null && cfg.indexer.enable);
        message = "services.wazuh-server.settings vulnerability detection requires services.wazuh-server.indexer.";
      }
    ];
  };
}
