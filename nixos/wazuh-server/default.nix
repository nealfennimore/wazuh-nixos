# The Wazuh server: manager daemons and the API, as systemd units.
#
# Scope of this revision (phases 2, 3 and 5 of PLANS/WAZUH_SERVER_NIXOS.md):
# the daemons start under the sandbox, remoted and authd listen, the API
# answers an authenticated request, api-users.nix sets the API user
# passwords from files, and with an indexer configured the setup unit
# writes the indexer credentials to the Wazuh keystore and filebeat.nix
# ships alerts. The cluster is a later phase.
#
# Layout. The agent module links the package trees into /var/ossec and lets
# every daemon read through the links. That does not work here: analysisd,
# remoted, monitord and wazuh-db call chroot(/var/ossec) before they read
# their rules, keys and queues (src/analysisd/analysisd.c:525,
# src/remoted/main.c:195, src/monitord/main.c:235, src/wazuh_db/main.c:175),
# and a link into /nix/store dangles inside that chroot. So everything a
# chrooting daemon reads is a real file under /var/ossec: the ruleset and
# internal_options.conf are copied from the package on every activation, and
# ossec.conf is installed as a file rather than linked. Trees that only the
# non-chrooting processes use (bin, lib, wodles, framework, api/scripts,
# agentless, integrations, templates) stay store links, as in the agent module.
#
# Identity. The daemons run as the wazuh user from the start. The privsep
# patch in pkgs/patches makes their own setuid/setgid calls no-ops, and the
# four that chroot get CAP_SYS_CHROOT and the chroot syscall, nothing else.
# The chroot is upstream's habit, not this module's security boundary; the
# systemd namespace is.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  wazuhUser = "wazuh";
  wazuhGroup = wazuhUser;
  stateDir = "/var/ossec";
  cfg = config.services.wazuh-server;
  pkg = cfg.package;

  # Where the setup unit installs the configured secrets and certificates.
  # The daemons that read them run as wazuh, and the configured source files
  # usually belong to root, so PID 1 reads the sources through LoadCredential
  # and the setup unit writes wazuh-readable copies here.
  credentialPaths = {
    indexerCa = "${stateDir}/etc/indexer-ca.pem";
    indexerCertificate = "${stateDir}/etc/indexer.pem";
    indexerKey = "${stateDir}/etc/indexer.key";
    authAgentCa = "${stateDir}/etc/agent-ca.pem";
  };

  # name -> source path. Every entry becomes a LoadCredential line on the
  # setup unit and a file under /var/ossec.
  credentials =
    optionalAttrs (cfg.auth.enable && cfg.auth.passwordFile != null) {
      "authd-pass" = cfg.auth.passwordFile;
    }
    // optionalAttrs (cfg.auth.enable && cfg.auth.tls != null) {
      "sslmanager-cert" = cfg.auth.tls.certificate;
      "sslmanager-key" = cfg.auth.tls.key;
    }
    // optionalAttrs (cfg.auth.enable && cfg.auth.agentCa != null) {
      "agent-ca" = cfg.auth.agentCa;
    }
    // optionalAttrs (cfg.api.tls != null) {
      "api-cert" = cfg.api.tls.certificate;
      "api-key" = cfg.api.tls.key;
    }
    // optionalAttrs (cfg.indexer != null) {
      "indexer-ca" = cfg.indexer.tls.ca;
      "indexer-cert" = cfg.indexer.tls.certificate;
      "indexer-key" = cfg.indexer.tls.key;
      "indexer-username" = cfg.indexer.usernameFile;
      "indexer-password" = cfg.indexer.passwordFile;
    }
    // mapAttrs' (id: s: nameValuePair "secret-${id}" s.source) allSecrets;

  # The listeners, integrations and GitHub module (runtime.nix). The XML is
  # placed by generate-server-config.nix; this file runs what it needs.
  runtime = import ./runtime-config.nix { inherit cfg lib; };
  # email, emailAlerts, reports and syslogOutput (optional-services.nix).
  optionalServices = import ./optional-services-config.nix { inherit cfg pkgs; };
  # Every secret that the setup unit installs, by id. Each source names
  # its target: "argv" for integration-secrets.py, "config" for a value
  # that a daemon reads from ossec.conf.
  allSecrets = runtime.secrets // optionalServices.secrets;
  argvSecrets = filterAttrs (_: s: s.target == "argv") allSecrets;
  configSecrets = filterAttrs (_: s: s.target == "config") allSecrets;
  lowPortListeners = filter (l: l.port < 1024) cfg.remote.listeners;

  # Where integration secrets live for integration-secrets.py. Readable by
  # the wazuh group, which integratord runs as.
  secretsDir = "${stateDir}/etc/secrets";

  # integrations/<name> as the module runs it: the packaged script under the
  # packaged interpreter, through integration-secrets.py. Upstream's wrapper
  # (integrations/<name> in the package) runs the same interpreter and
  # exports the same variable.
  integrationWrapper =
    name:
    pkgs.writeText "wazuh-integration-${name}" ''
      #!/bin/sh
      OPENSSL_armcap=0
      export OPENSSL_armcap
      exec ${stateDir}/framework/python/bin/python3 ${./integration-secrets.py} \
        ${secretsDir} ${stateDir}/integrations/${name}.py "$@"
    '';

  # What the setup unit accepts as a secret: one line of printable ASCII
  # without space, "<", "$" or "\". The Wazuh XML reader does not decode
  # entities, opens an element at "<" and expands "$name" when a <var> is
  # defined (src/os_xml/os_xml.c, os_xml_variables.c), and integratord
  # splits its command line on spaces. A value that any of them would change
  # is refused, not escaped.
  secretRule = ''
    read_secret() {
      local LC_ALL=C
      local value
      value=$(cat "$CREDENTIALS_DIRECTORY/secret-$1")
      case "$value" in
        "" | *[!!-~]* | *"<"* | *'$'* | *"\\"*)
          echo "wazuh-server-setup: secret $1 must be one line of printable ASCII without space, <, \$ or \\" >&2
          exit 1
          ;;
      esac
      printf '%s' "$value"
    }
  '';

  generatedConfig = import ./generate-server-config.nix { inherit cfg pkgs credentialPaths; };

  # api.yaml. JSON is valid YAML, and the API reads it with PyYAML. The key
  # and cert names are relative to api/configuration/ssl
  # (api/api/configuration.py, append_wazuh_prefixes). drop_privileges is
  # off because the unit already runs as wazuh; the setuid it would do is a
  # no-op at best.
  apiConfig = pkgs.writeText "api.yaml" (
    builtins.toJSON (
      recursiveUpdate {
        host = cfg.api.listenAddresses;
        port = cfg.api.port;
        drop_privileges = false;
        https = {
          enabled = true;
          key = "server.key";
          cert = "server.crt";
          use_ca = false;
          ca = "ca.crt";
          ssl_protocol = "auto";
          ssl_ciphers = "";
        };
        logs.level = cfg.api.logLevel;
      } cfg.api.settings
    )
  );

  # Package trees that only non-chrooting processes read. Store links; an
  # upgrade changes the link target.
  linkedPackageDirs = [
    "bin"
    "lib"
    "wodles"
    "framework"
    "agentless"
    "templates"
  ];

  # Package trees that a chrooting daemon reads. Real copies, refreshed on
  # every activation so an upgrade replaces them.
  copiedPackageDirs = [
    "ruleset"
    "etc/rootcheck"
  ];

  # Host state. Created once from the package skeleton, then left alone.
  stateDirs = [
    "queue"
    "logs"
    "var"
    "tmp"
    "stats"
    "backup"
  ];

  # Directories the daemons expect inside the state trees. install.sh creates
  # them (src/init/inst-functions.sh, InstallCommon/InstallLocal/
  # InstallServer); the package skeleton holds most of them, and this list
  # makes the rest exist on a tree that predates them.
  stateSubdirs = [
    "queue/alerts"
    "queue/sockets"
    "queue/db"
    "queue/diff"
    "queue/fim/db"
    "queue/syscollector/db"
    "queue/logcollector"
    "queue/rids"
    "queue/router"
    "queue/cluster"
    "queue/keystore"
    "queue/fts"
    "queue/agentless"
    "queue/tasks"
    "queue/vd"
    "queue/indexer"
    "logs/alerts"
    "logs/archives"
    "logs/firewall"
    "logs/cluster"
    "logs/api"
    "logs/wazuh"
    "var/run"
    "var/db"
    "var/multigroups"
    "var/upgrade"
    "var/wodles"
    "var/download"
    "var/incoming"
    "var/selinux"
    "backup/agents"
    "backup/db"
    "backup/shared"
    "backup/groups"
  ];

  # etc is mixed. These names belong to the host after their first copy; the
  # API and authd write some of them. Everything else in etc follows the
  # package.
  hostOwnedEtcDirs = [
    "shared"
    "lists"
    "rules"
    "decoders"
  ];

  preStart = ''
    if [ -L ${stateDir} ]; then
      rm ${stateDir}
    fi
    install -d -m 0750 -o root -g ${wazuhGroup} ${stateDir}
    # Normalize the old store-linked etc layout before installing its
    # package-owned rootcheck subtree. Keep authd's final directory mode
    # throughout restarts rather than temporarily dropping group write.
    if [ -L ${stateDir}/etc ]; then
      rm ${stateDir}/etc
    fi
    install -d -m 1770 -o root -g ${wazuhGroup} ${stateDir}/etc

    ${concatMapStringsSep "\n" (dir: ''
      rm -rf ${stateDir}/${dir}
      ln -s ${pkg}/${dir} ${stateDir}/${dir}
    '') linkedPackageDirs}

    # active-response/bin is a real sticky directory with one store link per
    # response program, as in the agent module: the firewall responses
    # create a lock directory beside themselves
    # (src/active-response/firewalls/default-firewall-drop.c:12, LOCK_PATH
    # active-response/bin/fw-drop), so execd needs the write, and the
    # sticky bit keeps the wazuh group from replacing the root-owned links.
    # The directory inode stays across activations because it is a mount
    # point in the execd namespace. Only the entries are refreshed.
    # restart-wazuh is absent from the package (pkgs/wazuh-server).
    if [ -L ${stateDir}/active-response ]; then
      rm ${stateDir}/active-response
    fi
    install -d -m 0750 -o root -g ${wazuhGroup} ${stateDir}/active-response
    install -d -m 1770 -o root -g ${wazuhGroup} ${stateDir}/active-response/bin
    find ${stateDir}/active-response/bin -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    for entry in ${pkg}/active-response/bin/*; do
      [ -e "$entry" ] || continue
      ln -s "$entry" ${stateDir}/active-response/bin/"$(basename "$entry")"
    done

    # A fresh copy, then a rename, so a daemon that starts during activation
    # never sees a half-copied tree. The staging name lives directly under
    # ${stateDir}, which only root can write. etc is 1770, so a staging name
    # inside it could be planted by the wazuh group between the rm and the
    # cp, and cp -R would follow a planted symlink. mv -T replaces a planted
    # symlink instead of following it and fails on a planted directory.
    ${concatMapStringsSep "\n" (dir:
      let staging = "${stateDir}/.${replaceStrings [ "/" ] [ "-" ] dir}.new"; in ''
      rm -rf ${staging}
      cp -R --no-preserve=ownership,mode ${pkg}/${dir} ${staging}
      chown -R root:${wazuhGroup} ${staging}
      find ${staging} -type d -exec chmod 0750 {} +
      find ${staging} -type f -exec chmod 0640 {} +
      rm -rf ${stateDir}/${dir}
      mv -T ${staging} ${stateDir}/${dir}
    '') copiedPackageDirs}

    # integrations: a real copy, not a store link. The packaged scripts find
    # logs/ and queue/sockets/ from dirname(dirname(realpath(__file__)))
    # (integrations/slack.py, virustotal.py), which behind a link is the
    # read-only store. Each program is replaced with the module's wrapper,
    # which runs the script through integration-secrets.py.
    rm -rf ${stateDir}/integrations.new
    cp -R --no-preserve=ownership,mode ${pkg}/integrations ${stateDir}/integrations.new
    chown -R root:${wazuhGroup} ${stateDir}/integrations.new
    chmod 0750 ${stateDir}/integrations.new
    find ${stateDir}/integrations.new -type f -exec chmod 0640 {} +
    for script in ${stateDir}/integrations.new/*.py; do
      [ -e "$script" ] || continue
      name=$(basename "$script" .py)
      rm -f ${stateDir}/integrations.new/"$name"
    done
    ${concatMapStringsSep "\n" (
      name:
      "install -m 0750 -o root -g ${wazuhGroup} ${integrationWrapper name} ${stateDir}/integrations.new/${name}"
    ) (unique (mapAttrsToList (_: i: i.name) cfg.integrations))}
    rm -rf ${stateDir}/integrations
    mv ${stateDir}/integrations.new ${stateDir}/integrations

    # State trees. The directory inodes are mount points in the daemon
    # namespaces (ReadWritePaths), so they are created when absent and never
    # removed; deleting a mount point detaches the mount in every namespace.
    ${concatMapStringsSep "\n" (dir: ''
      if [ -L ${stateDir}/${dir} ]; then
        rm ${stateDir}/${dir}
      fi
      if [ ! -d ${stateDir}/${dir} ]; then
        if [ -d ${pkg}/${dir} ]; then
          cp -R --no-preserve=ownership,mode ${pkg}/${dir} ${stateDir}/${dir}
        else
          install -d ${stateDir}/${dir}
        fi
      fi
    '') stateDirs}
    ${concatMapStringsSep "\n" (dir: ''
      install -d -m 0750 -o ${wazuhUser} -g ${wazuhGroup} ${stateDir}/${dir}
    '') stateSubdirs}
    for name in ossec.log ossec.json active-responses.log; do
      [ -e ${stateDir}/logs/"$name" ] || touch ${stateDir}/logs/"$name"
    done
    [ -e ${stateDir}/queue/agents-timestamp ] || touch ${stateDir}/queue/agents-timestamp

    # The MITRE database ships with the package and lives under var. The
    # upstream installer reinstalls it on every upgrade too.
    if [ -f ${pkg}/var/db/mitre.db ]; then
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} ${pkg}/var/db/mitre.db ${stateDir}/var/db/mitre.db
    fi
    if [ -f ${pkg}/queue/syscollector/norm_config.json ]; then
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} ${pkg}/queue/syscollector/norm_config.json \
        ${stateDir}/queue/syscollector/norm_config.json
    fi

    chown -R ${wazuhUser}:${wazuhGroup} ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)}
    find ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)} -type d -exec chmod 0750 {} +
    find ${concatStringsSep " " (map (dir: "${stateDir}/${dir}") stateDirs)} -type f -exec chmod 0640 {} +

    # etc: sticky and root-owned. authd creates client.keys in it, and the
    # host-owned subtrees belong to wazuh because the API edits rules, lists
    # and decoders and remoted writes the merged group configuration.
    ${concatMapStringsSep "\n" (dir: ''
      if [ -L ${stateDir}/etc/${dir} ]; then
        rm ${stateDir}/etc/${dir}
      fi
      if [ ! -d ${stateDir}/etc/${dir} ]; then
        if [ -d ${pkg}/etc/${dir} ]; then
          cp -R --no-preserve=ownership,mode ${pkg}/etc/${dir} ${stateDir}/etc/${dir}
        else
          install -d ${stateDir}/etc/${dir}
        fi
      fi
      chown -R ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/${dir}
      find ${stateDir}/etc/${dir} -type d -exec chmod 0770 {} +
      find ${stateDir}/etc/${dir} -type f -exec chmod 0660 {} +
    '') hostOwnedEtcDirs}
    install -d -m 0770 -o ${wazuhUser} -g ${wazuhGroup} ${stateDir}/etc/shared/default

    for name in client.keys local_internal_options.conf; do
      if [ -L ${stateDir}/etc/"$name" ]; then
        rm ${stateDir}/etc/"$name"
      fi
      if [ ! -e ${stateDir}/etc/"$name" ]; then
        if [ -e ${pkg}/etc/"$name" ]; then
          cp --no-preserve=ownership,mode ${pkg}/etc/"$name" ${stateDir}/etc/"$name"
        else
          touch ${stateDir}/etc/"$name"
        fi
      fi
    done
    chown ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/client.keys
    chmod 0640 ${stateDir}/etc/client.keys
    chown root:${wazuhGroup} ${stateDir}/etc/local_internal_options.conf
    chmod 0640 ${stateDir}/etc/local_internal_options.conf

    # Package-owned files in etc, as real copies for the chroot. A version
    # bump adds keys to internal_options.conf, and a daemon that does not
    # find one exits with "(2301): Definition not found".
    install -m 0640 -o root -g ${wazuhGroup} ${pkg}/etc/internal_options.conf ${stateDir}/etc/internal_options.conf
    ${
      if allSecrets == { } then
        ''
          install -m 0640 -o root -g ${wazuhGroup} ${generatedConfig} ${stateDir}/etc/ossec.conf
          rm -rf ${secretsDir}
        ''
      else
        ''
          # Secrets. etc belongs to the wazuh group and is writable for it,
          # so a predictable name in etc could be a link that wazuh planted.
          # Every file that holds a secret is written in a fresh directory
          # under /var/ossec, which only root can write, and then renamed
          # into etc. rename(2) replaces a planted link instead of following
          # it.
          ${secretRule}
          staging=$(mktemp -d ${stateDir}/.wazuh-server-setup.XXXXXX)
          trap 'rm -rf "$staging"' EXIT

          # The generated file holds @WAZUH_SECRET_<id>@ tokens for the
          # secrets that a daemon reads from ossec.conf itself. The values
          # go into the installed copy only. index() and substr() treat the
          # value as text, so no character in it is special.
          cp ${generatedConfig} "$staging/ossec.conf"
          chmod 0600 "$staging/ossec.conf"
          ${concatStringsSep "\n" (
            mapAttrsToList (id: _: ''
              value=$(read_secret ${id})
              TOKEN=${escapeShellArg (runtime.token id)} VALUE="$value" awk '
                BEGIN { t = ENVIRON["TOKEN"]; v = ENVIRON["VALUE"] }
                {
                  out = ""
                  while ((i = index($0, t)) > 0) {
                    out = out substr($0, 1, i - 1) v
                    $0 = substr($0, i + length(t))
                  }
                  print out $0
                }
              ' "$staging/ossec.conf" > "$staging/ossec.conf.next"
              mv "$staging/ossec.conf.next" "$staging/ossec.conf"
              if grep -qF ${escapeShellArg (runtime.token id)} "$staging/ossec.conf"; then
                echo "wazuh-server-setup: token for ${id} left in ossec.conf" >&2
                exit 1
              fi
            '') configSecrets
          )}

          # Integration secrets, for integration-secrets.py. The directory
          # is rebuilt on every activation, so a removed integration loses
          # its file.
          install -d -m 0750 -o root -g ${wazuhGroup} "$staging/secrets"
          ${concatStringsSep "\n" (
            mapAttrsToList (id: _: ''
              value=$(read_secret ${id})
              (umask 0077; printf '%s\n' "$value" > "$staging/secrets/${id}")
              chown root:${wazuhGroup} "$staging/secrets/${id}"
              chmod 0640 "$staging/secrets/${id}"
            '') argvSecrets
          )}

          # Every secret is valid. Install both.
          chown root:${wazuhGroup} "$staging/ossec.conf"
          chmod 0640 "$staging/ossec.conf"
          mv -T "$staging/ossec.conf" ${stateDir}/etc/ossec.conf
          rm -rf ${secretsDir}
          mv -T "$staging/secrets" ${secretsDir}
          rm -rf "$staging"
          trap - EXIT
        ''
    }

    # glibc reads /etc/localtime once, relative to the root of the process.
    # Inside the chroot that is this file, which is why the upstream
    # installer copies it (inst-functions.sh, InstallCommon). NixOS creates
    # /etc/localtime only when time.timeZone is set; without it the daemons
    # would log in UTC anyway, so UTC is what the copy falls back to.
    if [ -e /etc/localtime ]; then
      install -m 0640 -o root -g ${wazuhGroup} "$(readlink -f /etc/localtime)" ${stateDir}/etc/localtime
    else
      install -m 0640 -o root -g ${wazuhGroup} ${pkgs.tzdata}/share/zoneinfo/UTC ${stateDir}/etc/localtime
    fi

    # api: scripts from the store, configuration as host state. The API
    # creates its RBAC database, its JWT keys and, without configured TLS,
    # a self-signed pair under configuration.
    if [ -L ${stateDir}/api ]; then
      rm ${stateDir}/api
    fi
    install -d -m 0750 -o root -g ${wazuhGroup} ${stateDir}/api
    rm -rf ${stateDir}/api/scripts
    ln -s ${pkg}/api/scripts ${stateDir}/api/scripts
    install -d -m 0770 -o ${wazuhUser} -g ${wazuhGroup} \
      ${stateDir}/api/configuration ${stateDir}/api/configuration/ssl ${stateDir}/api/configuration/security
    install -m 0640 -o root -g ${wazuhGroup} ${apiConfig} ${stateDir}/api/configuration/api.yaml
    ${optionalString (cfg.api.tls != null) ''
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/api-cert" ${stateDir}/api/configuration/ssl/server.crt
      install -m 0600 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/api-key" ${stateDir}/api/configuration/ssl/server.key
    ''}

    ${optionalString cfg.auth.enable (
      if cfg.auth.tls != null then
        ''
          install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/sslmanager-cert" ${stateDir}/etc/sslmanager.cert
          install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/sslmanager-key" ${stateDir}/etc/sslmanager.key
        ''
      else
        ''
          # The same self-signed pair the upstream installer generates
          # (inst-functions.sh, GenerateAuthCert). Kept once made, so agents
          # that pinned it keep enrolling.
          if [ ! -f ${stateDir}/etc/sslmanager.key ] || [ ! -f ${stateDir}/etc/sslmanager.cert ]; then
            rm -f ${stateDir}/etc/sslmanager.key ${stateDir}/etc/sslmanager.cert
            ${pkg}/bin/wazuh-authd -C 365 -B 2048 \
              -K ${stateDir}/etc/sslmanager.key -X ${stateDir}/etc/sslmanager.cert \
              -S "/C=US/ST=California/CN=wazuh/"
          fi
          chown ${wazuhUser}:${wazuhGroup} ${stateDir}/etc/sslmanager.key ${stateDir}/etc/sslmanager.cert
          chmod 0640 ${stateDir}/etc/sslmanager.key ${stateDir}/etc/sslmanager.cert
        ''
    )}
    ${optionalString (cfg.auth.enable && cfg.auth.passwordFile != null) ''
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/authd-pass" ${stateDir}/etc/authd.pass
    ''}
    ${optionalString (cfg.auth.enable && cfg.auth.agentCa != null) ''
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/agent-ca" ${credentialPaths.authAgentCa}
    ''}
    ${optionalString (cfg.indexer != null) ''
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/indexer-ca" ${credentialPaths.indexerCa}
      install -m 0640 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/indexer-cert" ${credentialPaths.indexerCertificate}
      install -m 0600 -o ${wazuhUser} -g ${wazuhGroup} "$CREDENTIALS_DIRECTORY/indexer-key" ${credentialPaths.indexerKey}

      # The indexer credentials for the manager itself. The indexer
      # connector (src/shared_modules/indexer_connector) reads them from the
      # Wazuh keystore, a RocksDB at queue/keystore relative to the home,
      # and falls back to admin:admin with a warning when they are absent.
      # The vulnerability scanner and the inventory harvester, both loaded
      # by wazuh-modulesd, are its users. wazuh-keystore writes the store
      # (src/shared_modules/keystore/src/main.cpp; -vp reads one line from
      # a file) and the reader opens it read-write, so the result belongs
      # to wazuh. The store is rebuilt on every activation: the configured
      # files are the source of truth. keyStore.cpp decrypts a version 1
      # store with etc/sslmanager.key, so this runs after that file exists.
      rm -rf ${stateDir}/queue/keystore
      install -d -m 0750 -o ${wazuhUser} -g ${wazuhGroup} ${stateDir}/queue/keystore
      ${pkg}/bin/wazuh-keystore -f indexer -k username -vp "$CREDENTIALS_DIRECTORY/indexer-username"
      ${pkg}/bin/wazuh-keystore -f indexer -k password -vp "$CREDENTIALS_DIRECTORY/indexer-password"
      chown -R ${wazuhUser}:${wazuhGroup} ${stateDir}/queue/keystore
      chmod -R o-rwx ${stateDir}/queue/keystore
    ''}
  '';

  # The daemons, in the order src/init/wazuh-server.sh starts them, minus
  # the ones this revision does not run: clusterd and agentlessd (optional
  # upstream). execd is conditional on activeResponse.enable, integratord
  # on integrations, maild on email.enable and csyslogd on syslogOutput.
  #
  # chroot: the daemon calls chroot(home) after reading its configuration.
  # writable: state outside the four shared trees that this daemon writes.
  daemons = {
    wazuh-db = {
      chroot = true;
      after = [ ];
    };
    # analysisd compiles each CDB list beside its source in etc/lists on
    # start (lists_make.c), and writes the active-response map
    # etc/shared/ar.conf that it pushes to agents (active-response.c:46,
    # DEFAULTAR). Both subtrees are writable for it; the rest of etc is not.
    wazuh-analysisd = {
      chroot = true;
      after = [ "wazuh-db.service" ];
      writable = [
        "etc/lists"
        "etc/shared"
      ];
    };
    # remoted writes etc/shared/<group>/merged.mg, the configuration it
    # pushes to agents, and reads etc/client.keys that authd writes.
    #
    # Its main process forks one child per <remote> block and then returns
    # 0 (src/remoted/main.c, the loop over logr.conn), with or without -f.
    # Under Type=exec that return is a clean exit and the unit goes inactive
    # with the children still listening, until systemd stops the group.
    # Type=forking waits for the parent to exit. With one listener systemd
    # tracks the one surviving child as the main process, and
    # Restart=on-failure restarts it. With more than one there is no single
    # main process: GuessMainPID is off, the unit stays active while any
    # child runs, and Restart=always restarts it when the last one exits.
    # One listener that dies while another runs is not restarted, as with
    # the upstream wazuh-control.
    #
    # Each child binds its port after the chroot, as wazuh
    # (src/remoted/remoted.c, HandleRemote). A port below 1024 needs
    # CAP_NET_BIND_SERVICE.
    wazuh-remoted = {
      chroot = true;
      forking = true;
      after = [
        "wazuh-db.service"
        "wazuh-analysisd.service"
      ];
      writable = [ "etc/shared" ];
      serviceConfig =
        optionalAttrs (length cfg.remote.listeners > 1) {
          GuessMainPID = false;
          Restart = "always";
        }
        // optionalAttrs (lowPortListeners != [ ]) {
          CapabilityBoundingSet = chrootHardening.CapabilityBoundingSet ++ [ "CAP_NET_BIND_SERVICE" ];
          AmbientCapabilities = chrootHardening.AmbientCapabilities ++ [ "CAP_NET_BIND_SERVICE" ];
        };
    };
    wazuh-monitord = {
      chroot = true;
      after = [ "wazuh-analysisd.service" ];
    };
    wazuh-syscheckd = {
      after = [ "wazuh-analysisd.service" ];
    };
    wazuh-logcollector = {
      after = [ "wazuh-analysisd.service" ];
    };
    wazuh-modulesd = {
      after = [
        "wazuh-db.service"
        "wazuh-analysisd.service"
      ];
    };
  }
  // optionalAttrs cfg.auth.enable {
    # authd adds agents to etc/client.keys. etc is sticky and root-owned, and
    # the file belongs to wazuh, so the write needs the directory.
    wazuh-authd = {
      after = [ "wazuh-db.service" ];
      writable = [ "etc" ];
    };
  }
  // optionalAttrs cfg.activeResponse.enable {
    # execd runs the responses that an <active-response> block binds to the
    # manager itself (location server). It does not chroot, and its only
    # privilege call is Privsep_SetGroup (src/os_execd/main.c:115-123),
    # which the privsep patch makes a no-op. It binds queue/alerts/execq
    # (main.c:169) and queue/sockets/com (wcom.c:469), writes var/run, and
    # reads etc/shared/ar.conf (exec.c:42) that analysisd writes. So the
    # wazuh user with no capability is enough for the daemon.
    #
    # The response programs are another matter. Upstream runs execd as
    # root because firewall-drop and route-null need CAP_NET_ADMIN,
    # host-deny writes /etc/hosts.deny and disable-account needs a real
    # uid of 0 (the agent module's responseRequirements table has the
    # source lines). The upstream manager configuration binds none of them:
    # it defines the <command> blocks and leaves <active-response>
    # commented out (etc/templates/config/generic/ar-definitions.template),
    # so by default no program runs on the manager, and nothing here
    # grants what a program needs. An operator who adds a server-side
    # response through extraConfig must also grant its needs to this unit.
    #
    # With active response disabled, execd logs "Active response disabled"
    # and returns 0 (execd.c:574-577), so the unit is absent rather than
    # inactive forever, and the generated ossec.conf tells analysisd the
    # same through <active-response><disabled>yes</disabled>.
    wazuh-execd = {
      after = [ "wazuh-db.service" ];
      writable = [ "active-response" ];
    };
  }
  // optionalAttrs (cfg.integrations != { }) {
    # integratord reads logs/alerts/alerts.json and runs
    # integrations/<name> for each matching alert (src/os_integrator). It
    # does not chroot. It writes the alert and options files to /tmp, which
    # is private to the unit, and the scripts append to
    # logs/integrations.log and send to queue/sockets/queue. The scripts are
    # Python with requests: MemoryDenyWriteExecute is off for the same
    # reason as on wazuh-apid, untested under that restriction. The
    # programs reach the integration services over the network.
    wazuh-integratord = {
      after = [ "wazuh-analysisd.service" ];
      serviceConfig.MemoryDenyWriteExecute = false;
    };
  }
  // optionalAttrs cfg.email.enable {
    # maild reads the alert file and mails what <email_alerts> and the
    # alert level select. With a relay host it resolves the name, then
    # calls chroot(home) (src/os_maild/maild.c:176-196), so it gets the
    # chroot capability. With sendmail it stays outside the chroot and runs
    # the wrapper that optional-services-config.nix writes.
    wazuh-maild = {
      chroot = cfg.email.smtpServer != null;
      after = [ "wazuh-analysisd.service" ];
    };
  }
  // optionalAttrs (cfg.syslogOutput != [ ]) {
    # csyslogd reads the alert file and sends each selected alert over UDP.
    # It does not chroot (src/os_csyslogd/main.c).
    wazuh-csyslogd = {
      after = [ "wazuh-analysisd.service" ];
    };
  };

  sharedWritableDirs = [
    "logs"
    "queue"
    "var"
    "tmp"
    "stats"
    "backup"
  ];

  writablePathsFor = unit: map (dir: "${stateDir}/${dir}") (sharedWritableDirs ++ (unit.writable or [ ]));

  apiWritable = {
    writable = [
      "api/configuration"
      "etc/rules"
      "etc/decoders"
      "etc/lists"
      "etc/shared"
    ];
  };

  # The agent module's sandbox, with its reasons. The two differences are
  # marked. ProtectSystem = "strict" leaves the root read-only; only the
  # paths in ReadWritePaths get a writable bind, and those are noexec.
  hardening = {
    CapabilityBoundingSet = [ "" ];
    AmbientCapabilities = [ "" ];
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = "read-only";
    PrivateTmp = true;
    ProtectClock = true;
    ProtectControlGroups = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    RemoveIPC = true;
    SystemCallArchitectures = "native";
    UMask = "0027";
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
      "AF_NETLINK"
    ];
    MemoryDenyWriteExecute = true;
    PrivateDevices = true;
    SystemCallFilter = [ "@system-service" ];
    # The upstream unit sets this; analysisd and wazuh-db raise their own
    # soft limit toward it at start (rlimit_nofile in internal_options.conf).
    LimitNOFILE = 65536;
  };

  # chroot(2) needs CAP_SYS_CHROOT, and the syscall is in @privileged, which
  # @system-service leaves out.
  chrootHardening = {
    CapabilityBoundingSet = [ "CAP_SYS_CHROOT" ];
    AmbientCapabilities = [ "CAP_SYS_CHROOT" ];
    SystemCallFilter = [
      "@system-service"
      "chroot"
    ];
  };

  mkService =
    name: unit:
    let
      chroot = unit.chroot or false;
    in
    {
      description = name;
      partOf = [ "wazuh-server.target" ];
      after = [
        "wazuh-server-setup.service"
        "network.target"
      ]
      ++ unit.after;
      requires = [ "wazuh-server-setup.service" ];
      path = cfg.path ++ [
        "/run/current-system/sw"
        "/run/wrappers"
      ];
      environment.WAZUH_HOME = stateDir;
      serviceConfig =
        hardening
        // optionalAttrs chroot chrootHardening
        // optionalAttrs (name == "wazuh-syscheckd") { IPAddressDeny = "any"; }
        // {
          Type = if unit.forking or false then "forking" else "exec";
          User = wazuhUser;
          Group = wazuhGroup;
          WorkingDirectory = "${stateDir}/";
          ReadWritePaths = writablePathsFor unit;
          NoExecPaths = writablePathsFor unit;
          # No -c. The default configuration path is etc/ossec.conf relative
          # to the home directory, and that stays valid on both sides of the
          # chroot. An absolute /var/ossec/etc/ossec.conf does not.
          ExecStart = "${pkg}/bin/${name} -f";
          Restart = "on-failure";
          RestartSec = 5;
        }
        // (unit.serviceConfig or { });
    };
in
{
  imports = [
    ./settings.nix
    # api.users and wazuh-api-users.service.
    ./api-users.nix
    # remote.listeners, integrations and github.
    ./runtime.nix
    # email, emailAlerts, reports and syslogOutput.
    ./optional-services.nix
    # Alert shipping. It reads services.wazuh-server.indexer and declares
    # services.wazuh-server.filebeat; the arguments are the static values
    # its unit shares with the daemons.
    (import ./filebeat.nix { inherit stateDir wazuhGroup hardening; })
  ];

  options.services.wazuh-server = {
    enable = mkEnableOption "the Wazuh server (manager and API)";

    package = mkPackageOption pkgs "wazuh-server" { };

    openFirewall = mkEnableOption "the agent, enrollment and API ports in the firewall";

    remote.port = mkOption {
      type = types.port;
      default = 1514;
      description = "Port remoted listens on for agent connections (TCP).";
    };

    listenIPv6 = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Bind remoted and authd to an IPv6 socket. On Linux that socket is
        dual-stack unless net.ipv6.bindv6only is set, so IPv4 agents keep
        connecting. Off, both daemons bind IPv4 only (the upstream
        default), and an agent that resolves the manager name to an IPv6
        address cannot connect.
      '';
    };

    auth = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Run wazuh-authd, the enrollment service.";
      };
      port = mkOption {
        type = types.port;
        default = 1515;
        description = "Enrollment port.";
      };
      passwordFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          File with the enrollment password. Read by PID 1, so it can be
          root-owned. null disables password enrollment.
        '';
      };
      tls = mkOption {
        type = types.nullOr (
          types.submodule {
            options = {
              certificate = mkOption {
                type = types.path;
                description = "Certificate authd presents to enrolling agents.";
              };
              key = mkOption {
                type = types.path;
                description = "Its private key. Keep it outside the Nix store.";
              };
            };
          }
        );
        default = null;
        description = ''
          The enrollment service certificate. null generates a self-signed
          pair once, the way the upstream installer does.
        '';
      };
      agentCa = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "CA that enrolling agents must present a certificate from. null accepts any agent.";
      };
    };

    api = {
      port = mkOption {
        type = types.port;
        default = 55000;
        description = "API port (HTTPS).";
      };
      listenAddresses = mkOption {
        type = types.listOf types.str;
        default = [
          "0.0.0.0"
          "::"
        ];
        description = "Addresses the API binds.";
      };
      tls = mkOption {
        type = types.nullOr (
          types.submodule {
            options = {
              certificate = mkOption {
                type = types.path;
                description = "API server certificate.";
              };
              key = mkOption {
                type = types.path;
                description = "Its private key. Keep it outside the Nix store.";
              };
            };
          }
        );
        default = null;
        description = "The API certificate. null makes the API generate a self-signed pair on first start.";
      };
      logLevel = mkOption {
        type = types.enum [
          "debug2"
          "debug"
          "info"
          "warning"
          "error"
          "critical"
        ];
        default = "info";
        description = "API log level.";
      };
      settings = mkOption {
        type = types.attrs;
        default = { };
        description = "Extra api.yaml settings, merged over the generated ones.";
      };
    };

    indexer = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            hosts = mkOption {
              type = types.listOf types.str;
              example = [ "https://indexer:9200" ];
              description = "Indexer URLs.";
            };
            tls = {
              ca = mkOption {
                type = types.path;
                description = "CA the indexer certificates chain to.";
              };
              certificate = mkOption {
                type = types.path;
                description = "Client certificate for the indexer.";
              };
              key = mkOption {
                type = types.path;
                description = "Its private key. Keep it outside the Nix store.";
              };
            };
            usernameFile = mkOption {
              type = types.path;
              example = "/run/secrets/wazuh-indexer-username";
              description = ''
                File with the indexer user name, one line. Read by PID 1
                through LoadCredential, so it can be root-owned. The setup
                unit writes it to the Wazuh keystore for the manager, and
                filebeat authenticates with it.
              '';
            };
            passwordFile = mkOption {
              type = types.path;
              example = "/run/secrets/wazuh-indexer-password";
              description = "File with that user's password, one line. Same handling as usernameFile.";
            };
          };
        }
      );
      default = null;
      description = ''
        The indexer connection. It drives the ossec.conf <indexer> block,
        the manager's keystore entries and the filebeat output
        (services.wazuh-server.filebeat). null disables the indexer block,
        vulnerability detection and filebeat.
      '';
    };

    activeResponse.enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Run wazuh-execd on the manager and write the upstream default
        <command> definitions to ossec.conf, as the upstream manager does.
        No <active-response> block is written, so no response runs until
        extraConfig adds one. The unit runs as wazuh with no capability;
        see the daemon table in the module for what the stock response
        programs need beyond that. false removes the unit and writes
        <active-response><disabled>yes</disabled>.
      '';
    };

    logAll = mkOption {
      type = types.bool;
      default = false;
      description = "Archive every event, not only alerts (logs/archives).";
    };

    alertLevel = mkOption {
      type = types.ints.between 0 16;
      default = 3;
      description = "Minimum rule level that produces an alert.";
    };

    extraConfig = mkOption {
      type = types.lines;
      default = "";
      description = "XML appended inside <ossec_config>.";
    };

    path = mkOption {
      type = types.listOf types.package;
      default = [ ];
      description = "Packages added to the daemons' PATH, for command readers and integrations.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        # Both modules own /var/ossec and the wazuh account. Upstream has no
        # agent on a manager host either: the manager monitors itself.
        assertion = !(config.services.wazuh-agent.enable or false);
        message = "services.wazuh-server and services.wazuh-agent cannot be enabled on the same host.";
      }
    ];

    users.users.${wazuhUser} = {
      isSystemUser = true;
      group = wazuhGroup;
      description = "Wazuh server user";
      home = stateDir;
    };
    users.groups.${wazuhGroup} = { };

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall (
      map (l: l.port) (filter (l: elem "tcp" l.protocol) cfg.remote.listeners)
      ++ [ cfg.api.port ]
      ++ optional cfg.auth.enable cfg.auth.port
    );
    networking.firewall.allowedUDPPorts = mkIf cfg.openFirewall (
      map (l: l.port) (filter (l: elem "udp" l.protocol) cfg.remote.listeners)
    );

    systemd.tmpfiles.rules = [
      "d ${stateDir} 0750 root ${wazuhGroup} -"
    ];

    systemd.targets.wazuh-server = {
      description = "Wazuh server";
      wantedBy = [ "multi-user.target" ];
      wants = map (name: "${name}.service") (attrNames daemons) ++ [ "wazuh-apid.service" ];
    };

    systemd.services = mapAttrs mkService daemons // {
      wazuh-server-setup = {
        description = "Set up the Wazuh server directory structure";
        wantedBy = [ "wazuh-server.target" ];
        before = map (name: "${name}.service") (attrNames daemons) ++ [ "wazuh-apid.service" ];
        environment.WAZUH_HOME = stateDir;
        serviceConfig = hardening // {
          Type = "oneshot";
          User = "root";
          Group = "root";
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_OVERRIDE"
            "CAP_FOWNER"
          ];
          PrivateNetwork = true;
          # "full", not "strict" with a bind over /var/ossec: see the agent
          # module's setup unit for the mount propagation this avoids. The
          # script's explicit paths bound what it changes.
          ProtectSystem = "full";
          ReadWritePaths = [ ];
          NoExecPaths = [ ];
          LoadCredential = mapAttrsToList (name: source: "${name}:${toString source}") credentials;
          ExecStart =
            let
              script = pkgs.writeShellApplication {
                name = "wazuh-server-setup";
                runtimeInputs = [
                  pkgs.coreutils
                  pkgs.findutils
                  pkgs.gawk
                  pkgs.gnugrep
                ];
                text = preStart;
              };
            in
            "${script}/bin/wazuh-server-setup";
        };
      };

      # The API. A Python process under the package's own interpreter; the
      # bin/wazuh-apid wrapper derives the home from its own location, which
      # is the store, so the interpreter and the script are named directly.
      # WAZUH_HOME governs every runtime path through the runtime-home patch
      # (pkgs/wazuh-server/patches/08-python-runtime-home.patch).
      wazuh-apid = {
        description = "Wazuh API";
        partOf = [ "wazuh-server.target" ];
        after = [
          "wazuh-server-setup.service"
          "network.target"
          "wazuh-db.service"
          "wazuh-analysisd.service"
        ];
        requires = [ "wazuh-server-setup.service" ];
        path = cfg.path ++ [
          "/run/current-system/sw"
          "/run/wrappers"
        ];
        environment.WAZUH_HOME = stateDir;
        serviceConfig =
          hardening
          // {
            Type = "exec";
            User = wazuhUser;
            Group = wazuhGroup;
            WorkingDirectory = "${stateDir}/";
            # Its own configuration, plus the etc subtrees the API edits:
            # uploaded rules, decoders and lists, and the group
            # configurations under etc/shared.
            ReadWritePaths = writablePathsFor apiWritable;
            NoExecPaths = writablePathsFor apiWritable;
            # Difference from the daemons: uvloop, cffi and the cryptography
            # bindings are untested under this restriction. Off until
            # checks.server proves it on.
            MemoryDenyWriteExecute = false;
            ExecStart = "${pkg}/framework/python/bin/python3 ${pkg}/api/scripts/wazuh_apid.py -f";
            Restart = "on-failure";
            RestartSec = 5;
          };
      };
    };
  };
}
