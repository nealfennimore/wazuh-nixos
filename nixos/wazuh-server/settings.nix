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
  ];
  valueType = types.nullOr (
    types.oneOf [
      types.str
      types.int
      types.bool
      (types.listOf valueType)
      (types.attrsOf valueType)
    ]
  );
  enabled = value: value == true || value == "yes";
  disabled = value: value == true || value == "yes";
in
{
  options.services.wazuh-server.settings = mkOption {
    type = types.attrsOf valueType;
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
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (section: builtins.elem section sections) (builtins.attrNames cfg.settings);
        message = "services.wazuh-server.settings supports only: ${lib.concatStringsSep ", " sections}. Use dedicated options for managed sections.";
      }
      {
        assertion = !(enabled (cfg.settings.global.email_notification or false));
        message = "services.wazuh-server does not run maild; email_notification must remain disabled.";
      }
      {
        assertion =
          !(cfg.settings ? cluster)
          || cfg.settings.cluster == null
          || disabled (cfg.settings.cluster.disabled or false);
        message = "services.wazuh-server does not run clusterd; a configured cluster must have disabled = true.";
      }
      {
        assertion =
          !(enabled (cfg.settings.vulnerability-detection.enabled or false)) || cfg.indexer != null;
        message = "services.wazuh-server.settings vulnerability detection requires services.wazuh-server.indexer.";
      }
    ];
  };
}
