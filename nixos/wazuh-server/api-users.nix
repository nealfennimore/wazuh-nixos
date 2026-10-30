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
#   3. Otherwise authenticate with the upstream default password, look the
#      user id up in GET /security/users, PUT the new password, and prove it
#      by authenticating with it.
#   4. If neither password authenticates, fail with a message. The password
#      was changed outside this unit, and the unit refuses to guess.
#
# The policy that the API enforces (framework/wazuh/security.py:23,227): 8
# to 64 characters with an upper-case letter, a lower-case letter, a digit
# and a character outside [A-Za-z0-9].
#
# Scope. The built-in users only. A user that does not exist yet needs an
# administrator token to create, and this unit holds no token except the
# one each user obtains for itself. Both built-in users carry the
# administrator role, which grants security:update on user:id:*.
#
# Transport. The unit talks to https://<api.serverName>:<api.port>. With
# api.tls set, curl verifies the server against the installed certificate
# copy under api/configuration/ssl/server.crt: a self-signed certificate is
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

  # How long the unit waits for the API to answer at all. The API starts a
  # process pool and loads its RBAC database. On the test VM that takes a
  # few minutes after the unit becomes active.
  waitSeconds = 600;

  script = pkgs.writeShellApplication {
    name = "wazuh-api-users";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.curl
      pkgs.jq
    ];
    text = ''
      umask 077
      base="https://${cfg.api.serverName}:${toString cfg.api.port}"
      ${
        if cfg.api.tls != null then
          ''tls=(--cacert ${stateDir}/api/configuration/ssl/server.crt)''
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
      bodyfile="$work/body.json"
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
      # command substitution and a variable does not come back.
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

      # set_password NAME DEFAULT FILE
      set_password() {
        local name=$1 default=$2 file=$3
        local wanted token id response
        wanted=$(cat "$file")
        if [ -z "$wanted" ]; then
          echo "$name: the password file is empty" >&2
          exit 1
        fi
        if authenticate "$name" "$wanted" > /dev/null; then
          echo "$name: the password is current"
          return 0
        fi
        if ! token=$(authenticate "$name" "$default"); then
          echo "$name: neither the configured password nor the upstream default authenticates (last HTTP status $(cat "$codefile")). The password was changed outside this unit. Put the current password in passwordFile, or reset it through the API." >&2
          exit 1
        fi
        response=$(api "$token" GET /security/users)
        if ! id=$(printf '%s' "$response" \
          | jq -er --arg n "$name" '.data.affected_items[] | select(.username == $n) | .id'); then
          echo "$name: not found in GET /security/users: $response" >&2
          exit 1
        fi
        jq -n --arg p "$wanted" '{password: $p}' > "$bodyfile"
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
          "set_password ${escapeShellArg name} ${escapeShellArg user.defaultPassword} \"$CREDENTIALS_DIRECTORY/${credentialName name}\""
        ) cfg.api.users
      )}
    '';
  };
in
{
  options.services.wazuh-server.api = {
    users = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
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
              defaultPassword = mkOption {
                type = types.str;
                default = name;
                defaultText = literalExpression "name";
                description = ''
                  The password the user has before this module changes it.
                  Upstream ships every built-in user with its own name as
                  the password. The unit authenticates with it only when
                  passwordFile does not authenticate.
                '';
              };
            };
          }
        )
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
        upstream default password stays, which is the user name.
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
      serviceConfig = {
        Type = "oneshot";
        # Active after success, so the target and systemctl status show the
        # result. A restart runs the script again, and the script does
        # nothing when the passwords are already current.
        RemainAfterExit = true;
        User = wazuhUser;
        Group = wazuhGroup;
        TimeoutStartSec = waitSeconds + 120;
        LoadCredential = mapAttrsToList (
          name: user: "${credentialName name}:${toString user.passwordFile}"
        ) cfg.api.users;
        ExecStart = "${script}/bin/wazuh-api-users";

        # The daemons' sandbox from default.nix, for a process that writes
        # nothing but its private /tmp: no capability, read-only root, no
        # writable path at all.
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
        # AF_UNIX for the name service socket, the two INET families for
        # the API.
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };
  };
}
