{ config, lib, pkgs, ... }:
let
  inherit (lib) mkEnableOption mkOption types;
  cfg = config.services.wazuh-indexer;
  home = "${cfg.package}/share/wazuh-indexer";
  runtime = "/run/wazuh-indexer";
  fileOption = description: mkOption { type = types.str; inherit description; };
  settings = cfg.settings // {
    "network.host" = cfg.listenAddress;
    "http.port" = cfg.port;
    "transport.port" = cfg.transportPort;
    "node.name" = cfg.nodeName;
    "cluster.name" = cfg.clusterName;
    "path.data" = "/var/lib/wazuh-indexer";
    "path.logs" = "/var/log/wazuh-indexer";
    "plugins.security.ssl.http.enabled" = true;
    "plugins.security.ssl.http.pemcert_filepath" = "node.pem";
    "plugins.security.ssl.http.pemkey_filepath" = "node.key";
    "plugins.security.ssl.http.pemtrustedcas_filepath" = "ca.pem";
    "plugins.security.ssl.transport.pemcert_filepath" = "node.pem";
    "plugins.security.ssl.transport.pemkey_filepath" = "node.key";
    "plugins.security.ssl.transport.pemtrustedcas_filepath" = "ca.pem";
    "plugins.security.ssl.transport.enforce_hostname_verification" = true;
    "plugins.security.authcz.admin_dn" = cfg.admin.distinguishedNames;
    "plugins.security.nodes_dn" = cfg.nodeDistinguishedNames;
    "plugins.security.allow_default_init_securityindex" = false;
    "compatibility.override_main_response_version" = true;
  } // lib.optionalAttrs cfg.singleNode { "discovery.type" = "single-node"; };
  generated = pkgs.writeText "opensearch.yml" (builtins.toJSON settings);
  userNames = builtins.attrNames cfg.users;
  usersSpec = pkgs.writeText "indexer-users.json" (builtins.toJSON (lib.imap0 (i: name: {
    inherit name;
    credential = "user-${toString i}";
    backend_roles = cfg.users.${name}.backendRoles;
  }) userNames));
  credentials = [ "ca:${cfg.tls.ca}" "certificate:${cfg.tls.certificate}" "key:${cfg.tls.key}" ];
  hardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    RestrictSUIDSGID = true;
    CapabilityBoundingSet = "";
    UMask = "0077";
  };
in {
  options.services.wazuh-indexer = {
    enable = mkEnableOption "the Wazuh indexer";
    package = mkOption { type = types.package; default = pkgs.callPackage ../../pkgs/wazuh-indexer { }; defaultText = lib.literalExpression "pkgs.callPackage ../../pkgs/wazuh-indexer { }"; };
    listenAddress = mkOption { type = types.str; default = "127.0.0.1"; };
    port = mkOption { type = types.port; default = 9200; };
    transportPort = mkOption { type = types.port; default = 9300; };
    openFirewall = mkEnableOption "the indexer HTTP firewall port (transport remains explicit)";
    nodeName = mkOption { type = types.str; default = config.networking.hostName; };
    clusterName = mkOption { type = types.str; default = "wazuh-cluster"; };
    singleNode = mkOption { type = types.bool; default = true; description = "Use single-node discovery. For clusters disable this and configure discovery in settings."; };
    heapSize = mkOption { type = types.strMatching "[1-9][0-9]*[mgMG]"; default = "1g"; };
    nodeDistinguishedNames = mkOption { type = types.listOf types.str; description = "Exact trusted node certificate subject DNs."; };
    tls = {
      ca = fileOption "Runtime CA certificate file.";
      certificate = fileOption "Runtime node certificate file with a DNS SAN matching nodeName.";
      key = fileOption "Runtime unencrypted PKCS#8 private key; keep outside the Nix store.";
    };
    admin = {
      certificate = fileOption "Runtime securityadmin client certificate.";
      key = fileOption "Runtime securityadmin PKCS#8 private key; never passed to the indexer daemon.";
      distinguishedNames = mkOption { type = types.listOf types.str; description = "Exact admin certificate subject DNs."; };
      host = mkOption { type = types.str; default = cfg.nodeName; description = "DNS name used by securityadmin; must match the node certificate SAN."; };
    };
    users = mkOption {
      default = { };
      description = "Declarative internal users. Reapplied on restart; upstream demo users are excluded.";
      type = types.attrsOf (types.submodule {
        options = {
          passwordHashFile = fileOption "Runtime file containing a bcrypt password hash.";
          backendRoles = mkOption { type = types.listOf types.str; default = [ ]; };
        };
      });
    };
    settings = mkOption { type = types.attrsOf types.anything; default = { }; description = "Additional OpenSearch settings. Module-owned TLS, state paths and endpoints take precedence."; };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = cfg.users != { }; message = "wazuh-indexer.users must contain explicit users; demo passwords are never installed."; }
      { assertion = cfg.nodeDistinguishedNames != [ ] && cfg.admin.distinguishedNames != [ ]; message = "wazuh-indexer requires trusted node and admin certificate DNs."; }
    ];
    users.groups.wazuh-indexer = { };
    users.users.wazuh-indexer = { isSystemUser = true; group = "wazuh-indexer"; };
    boot.kernel.sysctl."vm.max_map_count" = lib.mkDefault 262144;
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    systemd.services.wazuh-indexer = {
      description = "Wazuh indexer";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" "wazuh-indexer-security.service" ];
      after = [ "network-online.target" ];
      path = [ pkgs.coreutils pkgs.gnused ];
      environment = {
        OPENSEARCH_PATH_CONF = runtime;
        OPENSEARCH_TMPDIR = "/var/lib/wazuh-indexer/tmp";
      };
      preStart = ''
        cp -r ${home}/config/. ${runtime}/
        chmod -R u+w ${runtime}
        cp ${generated} ${runtime}/opensearch.yml
        install -m600 "$CREDENTIALS_DIRECTORY/ca" ${runtime}/ca.pem
        install -m600 "$CREDENTIALS_DIRECTORY/certificate" ${runtime}/node.pem
        install -m600 "$CREDENTIALS_DIRECTORY/key" ${runtime}/node.key
        sed -i -e '/^-Xms/d' -e '/^-Xmx/d' \
          -e 's|/etc/wazuh-indexer|${runtime}|g' ${runtime}/jvm.options
        printf '\n-Xms${cfg.heapSize}\n-Xmx${cfg.heapSize}\n' >> ${runtime}/jvm.options
        mkdir -p /var/lib/wazuh-indexer/tmp
      '';
      serviceConfig = hardening // {
        User = "wazuh-indexer";
        Group = "wazuh-indexer";
        ExecStart = "${cfg.package}/bin/wazuh-indexer";
        StateDirectory = "wazuh-indexer";
        LogsDirectory = "wazuh-indexer";
        RuntimeDirectory = "wazuh-indexer";
        RuntimeDirectoryMode = "0700";
        LoadCredential = credentials;
        LimitNOFILE = 65536;
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStartSec = 180;
      };
    };
    systemd.services.wazuh-indexer-security = {
      description = "Apply Wazuh indexer security configuration";
      after = [ "wazuh-indexer.service" ];
      requires = [ "wazuh-indexer.service" ];
      partOf = [ "wazuh-indexer.service" ];
      path = [ pkgs.coreutils pkgs.python3 ];
      script = ''
        cp -r ${home}/config/opensearch-security/. /run/wazuh-indexer-security/
        chmod -R u+w /run/wazuh-indexer-security
        python3 ${./users.py} ${usersSpec} /run/wazuh-indexer-security/internal_users.yml
        exec ${cfg.package}/bin/wazuh-indexer-securityadmin \
          -h ${lib.escapeShellArg cfg.admin.host} -p ${toString cfg.port} \
          -cn ${lib.escapeShellArg cfg.clusterName} \
          -cacert "$CREDENTIALS_DIRECTORY/ca" \
          -cert "$CREDENTIALS_DIRECTORY/certificate" -key "$CREDENTIALS_DIRECTORY/key" \
          -cd /run/wazuh-indexer-security
      '';
      serviceConfig = hardening // {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "wazuh-indexer-security";
        RuntimeDirectoryMode = "0700";
        LoadCredential = [ "ca:${cfg.tls.ca}" "certificate:${cfg.admin.certificate}" "key:${cfg.admin.key}" ]
          ++ lib.imap0 (i: name: "user-${toString i}:${cfg.users.${name}.passwordHashFile}") userNames;
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStartSec = 180;
      };
    };
  };
}
