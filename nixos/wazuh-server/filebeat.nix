# Alert shipping: filebeat reads logs/alerts/alerts.json and writes each
# alert to the indexer (phase 5 of PLANS/WAZUH_SERVER_NIXOS.md).
#
# Parity target. The upstream server package installs filebeat OSS 7.10.2
# with the Wazuh filebeat module (wazuh-filebeat-0.4.tar.gz), the index
# template extensions/elasticsearch/7.x/wazuh-template.json and the
# configuration extensions/filebeat/7.x/filebeat.yml, and runs filebeat as
# root with the indexer password in the filebeat keystore. This module
# differs in four places:
#
# - The filebeat binary is pkgs/filebeat-oss, the upstream filebeat OSS
#   7.10.2 rpm from the Wazuh package repository. nixpkgs filebeat7 (7.17)
#   is not usable: since 7.13 libbeat calls GET /_license on connect, and
#   the indexer answers "Invalid index name [_license]", so the output
#   never connects. The indexer announces itself as 7.10.2
#   (compatibility.override_main_response_version in nixos/wazuh-indexer),
#   which is the version this filebeat expects.
# - The module and the template come from the pinned wazuh source tree
#   (pkgs/common, extensions/filebeat/7.x/wazuh-module and
#   extensions/elasticsearch/7.x/wazuh-template.json at the packaged tag),
#   not from packages.wazuh.com. The tarball on packages.wazuh.com is the
#   same tree, packed.
# - Credentials never touch the store or the disk. The unit loads the
#   username and password files with LoadCredential and a wrapper exports
#   them to filebeat's environment; filebeat.yml references them as
#   ${INDEXER_USERNAME} and ${INDEXER_PASSWORD}. The TLS files are loaded
#   the same way and referenced through ${CREDENTIALS_DIRECTORY}.
# - filebeat runs as its own user, wazuh-filebeat, with the wazuh group as
#   a supplementary group. alerts.json is wazuh:wazuh 0640 and every
#   directory above it is group-traversable, so that is all it needs. It
#   writes only its registry, under /var/lib/wazuh-filebeat.
#
# Template loading. libbeat loads the template on every connection to the
# output when setup.template.enabled is on (the default), with the JSON
# file named here and setup.template.overwrite from upstream. That is what
# `filebeat setup --index-management` does, without a second process that
# must wait for the indexer. The module's ingest pipeline is loaded the
# same way, by the fileset, on connect.
#
# The arguments are the static values default.nix shares with its own
# units. The configuration itself is read from config, like any module.
{
  stateDir,
  wazuhGroup,
  hardening,
}:
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.services.wazuh-server;
  fb = cfg.filebeat;
  enabled = cfg.enable && cfg.indexer != null && fb.enable;

  filebeatUser = "wazuh-filebeat";

  common = import ../../pkgs/common { inherit (pkgs) fetchFromGitHub fetchurl lib; };

  # path.home for filebeat. It looks for modules under ${path.home}/module
  # (filebeat/fileset/modules.go), so the Wazuh module sits there under the
  # name the configuration uses. The template lives beside it.
  filebeatHome = pkgs.runCommand "wazuh-filebeat-home" { } ''
    install -d $out/module
    cp -R ${common.wazuhSrc}/extensions/filebeat/7.x/wazuh-module $out/module/wazuh
    chmod -R u+w $out/module/wazuh
    install -m 0444 ${common.wazuhSrc}/extensions/elasticsearch/7.x/wazuh-template.json $out/wazuh-template.json
    test -f $out/module/wazuh/module.yml
    test -f $out/module/wazuh/alerts/manifest.yml
    test -f $out/module/wazuh/alerts/ingest/pipeline.json
    test -f $out/module/wazuh/archives/manifest.yml
  '';

  # extensions/filebeat/7.x/filebeat.yml at the packaged tag, with the
  # output filled in. JSON is valid YAML. The seccomp block is upstream's:
  # the 7.10.2 policy (libbeat/common/seccomp/policy_linux_amd64.go) does
  # not list rseq, which glibc calls at start on current kernels.
  filebeatConfig = pkgs.writeText "filebeat.yml" (
    builtins.toJSON (
      {
        "filebeat.modules" = [
          {
            module = "wazuh";
            alerts = {
              enabled = true;
              "var.paths" = [ "${stateDir}/logs/alerts/alerts.json" ];
            };
            archives = {
              enabled = fb.archives;
              "var.paths" = [ "${stateDir}/logs/archives/archives.json" ];
            };
          }
        ];
        "setup.template.json.enabled" = true;
        "setup.template.json.path" = "${filebeatHome}/wazuh-template.json";
        "setup.template.json.name" = "wazuh";
        "setup.template.overwrite" = true;
        # wazuh-template.json is a legacy template (order, index_patterns,
        # settings and mappings at the top level). 7.10.2 defaults to
        # legacy; the key is explicit so that a newer filebeat, which
        # defaults to composable templates, does not post it to
        # _index_template, where this shape is rejected.
        "setup.template.type" = "legacy";
        "setup.ilm.enabled" = false;
        "output.elasticsearch" = {
          hosts = cfg.indexer.hosts;
          username = "\${INDEXER_USERNAME}";
          password = "\${INDEXER_PASSWORD}";
          "ssl.verification_mode" = "full";
          "ssl.certificate_authorities" = [ "\${CREDENTIALS_DIRECTORY}/indexer-ca" ];
          "ssl.certificate" = "\${CREDENTIALS_DIRECTORY}/indexer-cert";
          "ssl.key" = "\${CREDENTIALS_DIRECTORY}/indexer-key";
        };
        "logging.metrics.enabled" = false;
        seccomp = {
          default_action = "allow";
          syscalls = [
            {
              action = "allow";
              names = [ "rseq" ];
            }
          ];
        };
      }
      // fb.settings
    )
  );

  # filebeat reads its configuration from path.config. -c takes an absolute
  # path, so path.config only has to exist.
  configDir = pkgs.runCommand "wazuh-filebeat-config" { } ''
    install -d $out
    ln -s ${filebeatConfig} $out/filebeat.yml
  '';

  # The password file holds one line, like the one wazuh-keystore reads
  # (src/shared_modules/keystore/src/main.cpp reads with getline).
  start = pkgs.writeShellApplication {
    name = "wazuh-filebeat-start";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      INDEXER_USERNAME="$(head -n 1 "$CREDENTIALS_DIRECTORY/indexer-username")"
      INDEXER_PASSWORD="$(head -n 1 "$CREDENTIALS_DIRECTORY/indexer-password")"
      export INDEXER_USERNAME INDEXER_PASSWORD
      exec ${fb.package}/bin/filebeat -e \
        -c ${configDir}/filebeat.yml \
        --path.home ${filebeatHome} \
        --path.config ${configDir} \
        --path.data "$STATE_DIRECTORY" \
        --path.logs "$STATE_DIRECTORY/logs" \
        --strict.perms=false
    '';
  };
in
{
  options.services.wazuh-server.filebeat = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Ship alerts to the indexer with filebeat. Only takes effect when
        services.wazuh-server.indexer is set.
      '';
    };

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../../pkgs/filebeat-oss { };
      defaultText = literalExpression "pkgs.callPackage ../../pkgs/filebeat-oss { }";
      description = ''
        The filebeat package. The default is filebeat OSS 7.10.2, the
        version the upstream server ships. filebeat 7.13 and later refuse
        the indexer (see pkgs/filebeat-oss).
      '';
    };

    archives = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Also ship logs/archives/archives.json (every event, not only alerts)
        into wazuh-archives-4.x-*. Needs services.wazuh-server.logAll.
      '';
    };

    settings = mkOption {
      type = types.attrs;
      default = { };
      example = {
        "output.elasticsearch.bulk_max_size" = 1000;
      };
      description = "Extra filebeat.yml settings, merged over the generated ones. Dotted keys are accepted.";
    };
  };

  config = mkIf enabled {
    assertions = [
      {
        assertion = !fb.archives || cfg.logAll;
        message = "services.wazuh-server.filebeat.archives needs services.wazuh-server.logAll.";
      }
    ];

    users.users.${filebeatUser} = {
      isSystemUser = true;
      group = filebeatUser;
      description = "Wazuh alert shipper";
    };
    users.groups.${filebeatUser} = { };

    systemd.targets.wazuh-server.wants = [ "wazuh-filebeat.service" ];

    systemd.services.wazuh-filebeat = {
      description = "Wazuh alert shipping to the indexer (filebeat)";
      partOf = [ "wazuh-server.target" ];
      after = [
        "wazuh-server-setup.service"
        "network-online.target"
        "wazuh-analysisd.service"
      ];
      requires = [ "wazuh-server-setup.service" ];
      wants = [ "network-online.target" ];
      serviceConfig = hardening // {
        Type = "exec";
        User = filebeatUser;
        Group = filebeatUser;
        SupplementaryGroups = [ wazuhGroup ];
        StateDirectory = "wazuh-filebeat";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/wazuh-filebeat";
        LoadCredential = [
          "indexer-ca:${toString cfg.indexer.tls.ca}"
          "indexer-cert:${toString cfg.indexer.tls.certificate}"
          "indexer-key:${toString cfg.indexer.tls.key}"
          "indexer-username:${toString cfg.indexer.usernameFile}"
          "indexer-password:${toString cfg.indexer.passwordFile}"
        ];
        ExecStart = "${start}/bin/wazuh-filebeat-start";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
