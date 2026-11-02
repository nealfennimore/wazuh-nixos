# Generate one merged tree for configurable sections. Service-owned sections
# remain separate: their options also control credentials and systemd units.
{
  cfg,
  pkgs,
  credentialPaths,
}:
let
  inherit (pkgs) lib;
  xml = import ./xml.nix { inherit lib; };
  runtime = import ./runtime-config.nix { inherit cfg lib; };
  settingsRuntime = import ./settings-runtime.nix { inherit cfg lib; };
  optionalServices = import ./optional-services-config.nix { inherit cfg pkgs; };
  command = name: executable: {
    inherit name executable;
    timeout_allowed = true;
  };
  defaults = {
    global = {
      jsonout_output = true;
      alerts_log = true;
      logall = cfg.logAll;
      logall_json = cfg.logAll;
      email_notification = false;
      agents_disconnection_time = "15m";
      agents_disconnection_alert_time = 0;
      update_check = false;
    }
    // lib.optionalAttrs cfg.activeResponse.enable {
      white_list = [
        "127.0.0.1"
        "^localhost.localdomain$"
      ];
    };
    alerts = {
      log_alert_level = cfg.alertLevel;
      email_alert_level = 12;
    };
    logging.log_format = "plain";
    vulnerability-detection = {
      enabled = cfg.indexer != null && cfg.indexer.enable;
      index-status = true;
      feed-update-interval = "60m";
    };
    ruleset = {
      decoder_dir = [
        "ruleset/decoders"
        "etc/decoders"
      ];
      rule_dir = [
        "ruleset/rules"
        "etc/rules"
      ];
      rule_exclude = "0215-policy_rules.xml";
      list = [
        "etc/lists/audit-keys"
        "etc/lists/amazon/aws-eventnames"
        "etc/lists/security-eventchannel"
        "etc/lists/malicious-ioc/malware-hashes"
        "etc/lists/malicious-ioc/malicious-ip"
        "etc/lists/malicious-ioc/malicious-domains"
      ];
    };
    rule_test = {
      enabled = true;
      threads = 1;
      max_sessions = 64;
      session_timeout = "15m";
    };
    localfile = [
      {
        log_format = "syslog";
        location = "/var/ossec/logs/active-responses.log";
      }
    ];
  }
  // (
    if cfg.activeResponse.enable then
      {
        # restart-wazuh is intentionally absent: systemd owns process lifetime.
        command = [
          (command "disable-account" "disable-account")
          (command "firewall-drop" "firewall-drop")
          (command "host-deny" "host-deny")
          (command "route-null" "route-null")
          (command "win_route-null" "route-null.exe")
          (command "netsh" "netsh.exe")
        ];
      }
    else
      { active-response.disabled = true; }
  );
  settings = lib.recursiveUpdate (lib.recursiveUpdate defaults { global = optionalServices.global; }) settingsRuntime.settings;
  # ReadConfig processes sections in document order. Active responses look
  # up an already-read command, so alphabetical attribute order is invalid.
  sectionOrder = [
    "global"
    "alerts"
    "logging"
    "rootcheck"
    "wodle"
    "sca"
    "syscheck"
    "command"
    "active-response"
    "localfile"
    "ruleset"
    "rule_test"
    "cluster"
    "vulnerability-detection"
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
  renderedSettings = lib.concatMapStrings (
    name: xml.element name (settings.${name} or null)
  ) sectionOrder;
  indexer = xml.element "indexer" (
    if cfg.indexer == null then
      { enabled = false; }
    else
      {
        enabled = cfg.indexer.enable;
        hosts.host = cfg.indexer.hosts;
        ssl = {
          certificate_authorities.ca = [
            credentialPaths.indexerCa
          ]
          ++ (credentialPaths.indexerAdditionalCas or [ ]);
          certificate = credentialPaths.indexerCertificate;
          key = credentialPaths.indexerKey;
        };
      }
  );
  auth = xml.element "auth" (
    lib.recursiveUpdate (
      {
        disabled = !cfg.auth.enable;
        port = cfg.auth.port;
        ipv6 = cfg.listenIPv6;
        use_source_ip = false;
        purge = true;
        use_password = cfg.auth.passwordFile != null;
        ciphers = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH";
        ssl_verify_host = false;
        ssl_manager_cert = "etc/sslmanager.cert";
        ssl_manager_key = "etc/sslmanager.key";
        ssl_auto_negotiate = false;
      }
      // lib.optionalAttrs (cfg.auth.agentCa != null) {
        ssl_agent_ca = credentialPaths.authAgentCa;
      }
    ) (settingsRuntime.resolve cfg.auth.settings)
  );
in
pkgs.writeText "ossec.conf" ''
  <ossec_config>
  ${renderedSettings}
  ${runtime.remote}
  ${indexer}
  ${auth}
  ${runtime.integrations}
  ${runtime.github}${optionalServices.blocks}
  ${cfg.extraConfig}
  </ossec_config>
''
