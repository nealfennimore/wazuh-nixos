# API user passwords from files.
#
# Upstream's API starts with two users, wazuh and wazuh-wui, whose passwords
# equal their names (framework/wazuh/rbac/default/users.yaml at v4.14.8).
# Operators change them through PUT /security/users/{id} with a password
# body. The wazuh-passwords-tool does the same call. This module turns that
# step into a oneshot unit, wazuh-api-users.service, that runs after the API
# is up:
#
#   1. Wait until the API answers an HTTP request at all.
#   2. For each configured user, authenticate with the password from the
#      file. Success means the password is current and there is nothing to
#      do, so a second run of the unit is a no-op.
#   3. Otherwise authenticate with the previous password: the content of
#      defaultPasswordFile, or the upstream default. Look the user id up in
#      GET /security/users, PUT the new password, and prove it by
#      authenticating with it.
#   4. If neither password authenticates, fail with a message. The password
#      was changed outside this unit, and the unit refuses to guess.
#
# The policy that the API enforces (framework/wazuh/security.py:23,227): 8
# to 64 characters with an upper-case letter, a lower-case letter, a digit
# and a character outside [A-Za-z0-9].
#
# Secrets. Every password reaches the unit through LoadCredential and stays
# in files and shell variables. No password is an argument of an external
# command: /proc/<pid>/cmdline is readable by every local user, and NixOS
# mounts /proc without hidepid. curl reads the user and the bearer header
# from a config file, and jq reads the new password from stdin.
#
# Fail closed. The API itself does not know whether its users still carry
# the upstream defaults. When wazuh-api-users.service fails, for any reason
# including a missing credential file, OnFailure starts
# wazuh-apid-guard.service. The guard waits for the API, authenticates each
# configured user with the upstream default password, and stops
# wazuh-apid.service if any of them succeeds. A host whose provisioning
# failed on first boot then has no listening API instead of one that
# accepts wazuh:wazuh. The guard leaves the API alone when the defaults do
# not authenticate, so a later failure, such as a credential file that
# went missing after provisioning, does not take a provisioned API down.
# To recover, fix the file and restart wazuh-api-users.service, which
# starts the API again through Requires.
#
# Scope. The built-in users only. A user that does not exist yet needs an
# administrator token to create, and this unit holds no token except the
# one each user obtains for itself. Both built-in users carry the
# administrator role, which grants security:update on user:id:*.
#
# Transport. The unit talks to https://<api.serverName>:<api.port>. With
# api.tls set, curl verifies the server against api.tls.certificate, loaded
# through LoadCredential as api-cert: a self-signed certificate is
# its own anchor, and curl trusts a CA-signed leaf found in --cacert
# directly (X509_V_FLAG_PARTIAL_CHAIN, set by curl since 7.68). The host
# name must then be one the certificate names, which is why api.serverName
# exists. Without api.tls, the API generates a self-signed pair with no
# usable name on first start, and the unit connects to 127.0.0.1 with -k.
# The connection then stays on the host, and the password still travels
# encrypted, but the peer is not authenticated. Set api.tls to close that.
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

  # The names the unit accepts. See "Scope" above.
  builtinUsers = [
    "wazuh"
    "wazuh-wui"
  ];

  credentialName = name: "api-user-${name}";
  defaultCredentialName = name: "api-user-${name}-default";

  # The certificate curl verifies the API against, as a credential: the
  # installed copy under api/configuration/ssl sits in a directory only
  # wazuh can enter, and the guard runs as root without CAP_DAC_OVERRIDE.
  certCredential = optional (cfg.api.tls != null) "api-cert:${toString cfg.api.tls.certificate}";

  # How long the unit waits for the API to answer at all. The API starts a
  # process pool and creates its RBAC database. On a loaded test VM that
  # took over ten minutes once (635 s), so the budget is twenty.
  waitSeconds = 1200;

  # Shared by both scripts: the connection settings, a private work
  # directory, the wait for the API, and authenticate().
  prelude = ''
    umask 077
    base="https://${cfg.api.serverName}:${toString cfg.api.port}"
    ${
      if cfg.api.tls != null then
        ''tls=(--cacert "$CREDENTIALS_DIRECTORY/api-cert")''
      else
        ''tls=(--insecure)''
    }
    common=(--silent --show-error --max-time 30 "''${tls[@]}")

    # curl reads the user and the bearer header from a config file, so
    # neither appears on a command line that every process on the host can
    # read. The directory is the unit's private /tmp.
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    cfgfile="$work/curl.cfg"
    codefile="$work/code"

    # Escape a value for a double-quoted curl config string.
    quote() {
      local s=''${1//\\/\\\\}
      printf '%s' "''${s//\"/\\\"}"
    }

    # Any HTTP status means the API answers. 000 is curl's "no response".
    deadline=$((SECONDS + ${toString waitSeconds}))
    while :; do
      code=$(curl "''${common[@]}" -o /dev/null -w '%{http_code}' "$base/" || true)
      if [ "$code" != 000 ]; then
        break
      fi
      if [ "$SECONDS" -ge "$deadline" ]; then
        echo "the API at $base did not answer within ${toString waitSeconds} s" >&2
        exit 1
      fi
      sleep 2
    done

    # authenticate NAME PASSWORD: print a token, or return 1. The HTTP
    # status lands in $codefile, because the caller runs this in a
    # command substitution and a variable does not come back. printf is a
    # shell builtin, so the password is not a process argument.
    authenticate() {
      local out code body
      printf 000 > "$codefile"
      printf 'user = "%s:%s"\n' "$(quote "$1")" "$(quote "$2")" > "$cfgfile"
      out=$(curl "''${common[@]}" -K "$cfgfile" -X POST -w '\n%{http_code}' \
        "$base/security/user/authenticate?raw=true") || return 1
      code=''${out##*$'\n'}
      body=''${out%$'\n'*}
      printf '%s' "$code" > "$codefile"
      [ "$code" = 200 ] || return 1
      printf '%s' "$body"
    }
  '';

  script = pkgs.writeShellApplication {
    name = "wazuh-api-users";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.jq
    ];
    text = ''
      ${prelude}

      bodyfile="$work/body.json"

      # api TOKEN METHOD PATH [BODYFILE]: print the JSON response.
      api() {
        printf 'header = "Authorization: Bearer %s"\n' "$(quote "$1")" > "$cfgfile"
        if [ $# -ge 4 ]; then
          curl "''${common[@]}" -K "$cfgfile" -X "$2" \
            -H 'Content-Type: application/json' --data-binary "@$4" "$base$3"
        else
          curl "''${common[@]}" -K "$cfgfile" -X "$2" "$base$3"
        fi
      }

      # set_password NAME FILE [DEFAULTFILE]
      # FILE holds the password the user must have. DEFAULTFILE holds the
      # password the user has now. Without it, the upstream default applies,
      # which is the user name.
      set_password() {
        local name=$1 file=$2 defaultfile=''${3:-}
        local wanted default token id response
        wanted=$(cat "$file")
        if [ -z "$wanted" ]; then
          echo "$name: the password file is empty" >&2
          exit 1
        fi
        if [ -n "$defaultfile" ]; then
          default=$(cat "$defaultfile")
        else
          default=$name
        fi
        if authenticate "$name" "$wanted" > /dev/null; then
          echo "$name: the password is current"
          return 0
        fi
        if ! token=$(authenticate "$name" "$default"); then
          echo "$name: neither the configured password nor the previous password authenticates (last HTTP status $(cat "$codefile")). The password was changed outside this unit. Put the current password in defaultPasswordFile, or reset it through the API." >&2
          exit 1
        fi
        response=$(api "$token" GET /security/users)
        if ! id=$(printf '%s' "$response" \
          | jq -er --arg n "$name" '.data.affected_items[] | select(.username == $n) | .id'); then
          echo "$name: not found in GET /security/users: $response" >&2
          exit 1
        fi
        # The password goes to jq on stdin, never as an argument.
        printf '%s' "$wanted" | jq -Rs '{password: .}' > "$bodyfile"
        response=$(api "$token" PUT "/security/users/$id" "$bodyfile")
        if ! printf '%s' "$response" | jq -e '.error == 0 and .data.total_affected_items == 1' > /dev/null; then
          echo "$name: PUT /security/users/$id failed: $response" >&2
          exit 1
        fi
        if ! authenticate "$name" "$wanted" > /dev/null; then
          echo "$name: the API accepted the new password but does not authenticate with it (HTTP status $(cat "$codefile"))" >&2
          exit 1
        fi
        echo "$name: password set (user id $id)"
      }

      ${concatStringsSep "\n" (
        mapAttrsToList (
          name: user:
          "set_password ${escapeShellArg name} \"$CREDENTIALS_DIRECTORY/${credentialName name}\""
          + optionalString (
            user.defaultPasswordFile != null
          ) " \"$CREDENTIALS_DIRECTORY/${defaultCredentialName name}\""
        ) cfg.api.users
      )}
    '';
  };

  guard = pkgs.writeShellApplication {
    name = "wazuh-apid-guard";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.systemd
    ];
    text = ''
      ${prelude}

      live=0
      for name in ${concatMapStringsSep " " escapeShellArg (attrNames cfg.api.users)}; do
        if authenticate "$name" "$name" > /dev/null; then
          echo "$name: the upstream default password still authenticates"
          live=1
        else
          echo "$name: the upstream default password does not authenticate (HTTP status $(cat "$codefile"))"
        fi
      done
      if [ "$live" = 1 ]; then
        echo "stopping wazuh-apid.service: wazuh-api-users.service failed and a built-in user still has its upstream default password. Fix the password files, then restart wazuh-api-users.service." >&2
        systemctl stop wazuh-apid.service
        exit 1
      fi
      echo "no built-in user authenticates with its upstream default password; the API stays up"
    '';
  };

  # The daemons' sandbox from default.nix, for processes that write nothing
  # but their private /tmp: no capability, read-only root, no writable path
  # at all.
  sandbox = {
    CapabilityBoundingSet = [ "" ];
    AmbientCapabilities = [ "" ];
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
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
    SystemCallFilter = [ "@system-service" ];
    MemoryDenyWriteExecute = true;
    UMask = "0077";
    # AF_UNIX for the name service socket and the systemd bus, the two
    # INET families for the API.
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
    ];
  };
in
{
  options.services.wazuh-server.api = {
    users = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            passwordFile = mkOption {
              type = types.path;
              description = ''
                File with the password this user must have. Read by PID 1
                through LoadCredential, so it can be root-owned. Keep it
                outside the Nix store. The API requires 8 to 64 characters
                with an upper-case letter, a lower-case letter, a digit and
                a symbol.
              '';
            };
            defaultPasswordFile = mkOption {
              type = types.nullOr types.path;
              default = null;
              description = ''
                File with the password the user has before this module
                changes it. Read through LoadCredential like passwordFile.
                Keep it outside the Nix store. Without it the upstream
                default applies, which is the user name. The unit
                authenticates with this password only when passwordFile does
                not authenticate.
              '';
            };
          };
        }
      );
      default = { };
      example = literalExpression ''
        {
          wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
          wazuh-wui.passwordFile = "/run/secrets/wazuh-api-wui";
        }
      '';
      description = ''
        Passwords for the built-in API users wazuh and wazuh-wui, set by
        wazuh-api-users.service after the API starts. Without an entry the
        upstream default password stays, which is the user name. When the
        unit fails, wazuh-apid-guard.service stops the API if a configured
        user still authenticates with the upstream default.
      '';
    };

    serverName = mkOption {
      type = types.str;
      default = if cfg.api.tls != null then config.networking.hostName else "127.0.0.1";
      defaultText = literalExpression ''if api.tls != null then config.networking.hostName else "127.0.0.1"'';
      description = ''
        Host name that wazuh-api-users.service connects to. With api.tls
        set, it must be a name in the API certificate, because curl verifies
        the certificate against that name. Without api.tls, the unit
        connects with certificate verification off, and the default stays on
        the loopback interface.
      '';
    };
  };

  config = mkIf (cfg.enable && cfg.api.users != { }) {
    assertions = [
      {
        assertion = all (name: elem name builtinUsers) (attrNames cfg.api.users);
        message = "services.wazuh-server.api.users accepts only the built-in users: ${concatStringsSep ", " builtinUsers}.";
      }
    ];

    systemd.services.wazuh-api-users = {
      description = "Set the Wazuh API user passwords";
      wantedBy = [ "wazuh-server.target" ];
      requires = [ "wazuh-apid.service" ];
      after = [ "wazuh-apid.service" ];
      onFailure = [ "wazuh-apid-guard.service" ];
      serviceConfig = sandbox // {
        Type = "oneshot";
        # Active after success, so the target and systemctl status show the
        # result. A restart runs the script again, and the script does
        # nothing when the passwords are already current.
        RemainAfterExit = true;
        User = wazuhUser;
        Group = wazuhGroup;
        TimeoutStartSec = waitSeconds + 120;
        LoadCredential =
          certCredential
          ++
          mapAttrsToList (name: user: "${credentialName name}:${toString user.passwordFile}") cfg.api.users
          ++ mapAttrsToList (name: user: "${defaultCredentialName name}:${toString user.defaultPasswordFile}") (
            filterAttrs (_: user: user.defaultPasswordFile != null) cfg.api.users
          );
        ExecStart = "${script}/bin/wazuh-api-users";
      };
    };

    # Started by OnFailure of wazuh-api-users.service. Root, because it
    # stops a unit. It fails on purpose when it stops the API, so the
    # condition shows in systemctl --failed.
    systemd.services.wazuh-apid-guard = {
      description = "Stop the Wazuh API while a built-in user has its default password";
      after = [ "wazuh-apid.service" ];
      serviceConfig = sandbox // {
        Type = "oneshot";
        TimeoutStartSec = waitSeconds + 120;
        LoadCredential = certCredential;
        ExecStart = "${guard}/bin/wazuh-apid-guard";
      };
    };
  };
}
