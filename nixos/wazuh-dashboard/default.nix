{ config, lib, pkgs, ... }:
let
  inherit (lib) mkEnableOption mkOption types;
  cfg = config.services.wazuh-dashboard;
  runtime = "/run/wazuh-dashboard";
  state = "/var/lib/wazuh-dashboard";
  fileOption = description: mkOption { type = types.str; inherit description; };
  managers = lib.imap0 (i: manager: {
    id = "manager-${toString i}";
    inherit (manager) url port runAs;
  }) cfg.managers;
  settings = cfg.settings // {
    "server.host" = cfg.listenAddress;
    "server.port" = cfg.port;
    "server.ssl.enabled" = true;
    "server.ssl.certificate" = "${runtime}/certificate.pem";
    "server.ssl.key" = "${runtime}/key.pem";
    "opensearch.hosts" = cfg.indexer.hosts;
    "opensearch.ssl.verificationMode" = "full";
    "opensearch.ssl.certificateAuthorities" = [ "${runtime}/indexer-ca.pem" ];
    "opensearch.requestHeadersAllowlist" = [ "securitytenant" "Authorization" ];
    "opensearch_security.multitenancy.enabled" = false;
    "opensearch_security.readonly_mode.roles" = [ "kibana_read_only" ];
    "opensearch_security.cookie.secure" = true;
    "uiSettings.overrides.defaultRoute" = "/app/wz-home";
    "path.data" = state;
  };
  spec = pkgs.writeText "dashboard-settings.json" (builtins.toJSON { inherit managers settings; });
  managerCredentials = lib.concatLists (lib.imap0 (i: manager: [
    "manager-${toString i}-username:${manager.usernameFile}"
    "manager-${toString i}-password:${manager.passwordFile}"
  ] ++ lib.optional (manager.ca != null) "manager-${toString i}-ca:${manager.ca}") cfg.managers);
in {
  options.services.wazuh-dashboard = {
    enable = mkEnableOption "the Wazuh dashboard";
    package = mkOption { type = types.package; default = pkgs.callPackage ../../pkgs/wazuh-dashboard { }; defaultText = lib.literalExpression "pkgs.callPackage ../../pkgs/wazuh-dashboard { }"; };
    listenAddress = mkOption { type = types.str; default = "127.0.0.1"; };
    port = mkOption { type = types.port; default = 5601; };
    openFirewall = mkEnableOption "the dashboard HTTPS firewall port";
    tls = {
      certificate = fileOption "Runtime dashboard server certificate file.";
      key = fileOption "Runtime dashboard private key file; keep outside the Nix store.";
    };
    indexer = {
      hosts = mkOption { type = types.listOf types.str; description = "HTTPS indexer URLs, including ports."; };
      ca = fileOption "Runtime indexer CA certificate file.";
      usernameFile = fileOption "Runtime file containing the indexer service username (normally kibanaserver).";
      passwordFile = fileOption "Runtime file containing the indexer service password.";
    };
    managers = mkOption {
      default = [ ];
      type = types.listOf (types.submodule {
        options = {
          url = mkOption { type = types.strMatching "https://[^/]+"; description = "HTTPS manager origin, without a port or path; set port separately."; };
          port = mkOption { type = types.port; default = 55000; };
          usernameFile = fileOption "Runtime manager API username file.";
          passwordFile = fileOption "Runtime manager API password file.";
          runAs = mkOption { type = types.bool; default = false; };
          ca = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Additional manager CA file. All manager CAs form one process-wide NODE_EXTRA_CA_CERTS bundle; they are not isolated per manager. Null uses the bundled Node system/default trust, never disables verification. Indexer trust is configured explicitly with indexer.ca.";
          };
        };
      });
      description = "Manager API connections. Credentials are rendered at service start, outside the store.";
    };
    settings = mkOption { type = types.attrsOf types.anything; default = { }; description = "Extra dashboard settings; module-managed endpoints, TLS and state paths take precedence. Never place secrets here."; };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = cfg.indexer.hosts != [ ] && lib.all (lib.hasPrefix "https://") cfg.indexer.hosts; message = "wazuh-dashboard.indexer.hosts must contain HTTPS URLs."; }
      { assertion = cfg.managers != [ ]; message = "wazuh-dashboard.managers must contain at least one manager."; }
    ];
    users.groups.wazuh-dashboard = { };
    users.users.wazuh-dashboard = { isSystemUser = true; group = "wazuh-dashboard"; };
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    systemd.services.wazuh-dashboard = {
      description = "Wazuh dashboard";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      path = [ pkgs.coreutils pkgs.python3 ];
      environment = {
        OSD_PATH_CONF = runtime;
        NODE_EXTRA_CA_CERTS = "${runtime}/manager-ca.pem";
      };
      preStart = ''
        install -m600 "$CREDENTIALS_DIRECTORY/certificate" ${runtime}/certificate.pem
        install -m600 "$CREDENTIALS_DIRECTORY/key" ${runtime}/key.pem
        install -m600 "$CREDENTIALS_DIRECTORY/indexer-ca" ${runtime}/indexer-ca.pem
        python3 ${./configure.py} ${spec} ${runtime} ${state}
      '';
      serviceConfig = {
        User = "wazuh-dashboard";
        Group = "wazuh-dashboard";
        ExecStart = "${cfg.package}/bin/wazuh-dashboard --config ${runtime}/opensearch_dashboards.yml";
        StateDirectory = "wazuh-dashboard";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "wazuh-dashboard";
        RuntimeDirectoryMode = "0700";
        LoadCredential = [
          "certificate:${cfg.tls.certificate}" "key:${cfg.tls.key}"
          "indexer-ca:${cfg.indexer.ca}" "indexer-username:${cfg.indexer.usernameFile}"
          "indexer-password:${cfg.indexer.passwordFile}"
        ] ++ managerCredentials;
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        CapabilityBoundingSet = lib.optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
        AmbientCapabilities = lib.optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
