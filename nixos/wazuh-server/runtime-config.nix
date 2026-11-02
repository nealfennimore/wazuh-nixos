# The ossec.conf blocks for the options in runtime.nix: <remote>,
# <integration> and <github>. generate-server-config.nix places them.
#
# A secret is never written here. Each one becomes a token
# @WAZUH_SECRET_<id>@, and `secrets` tells default.nix where the value comes
# from and where it goes:
#
#   - argv: an integration secret. integratord passes <api_key> and
#     <hook_url> to the integration program as arguments
#     (src/os_integrator/integrator.c, exec_full_cmd), so the token stays in
#     ossec.conf and the module's integration wrapper replaces it inside the
#     Python process. The value never reaches a command line.
#   - config: the GitHub token. wazuh-modulesd reads it from ossec.conf and
#     sends it in a request header, so the setup unit writes the value into
#     /var/ossec/etc/ossec.conf.
{
  cfg,
  lib,
}:
let
  inherit (lib)
    concatMapStrings
    concatStringsSep
    concatMapStringsSep
    mapAttrsToList
    optionalString
    imap0
    ;

  yesNo = b: if b then "yes" else "no";
  # xml.nix refuses text that OS_XML cannot hold, such as "<" in a public
  # hook URL or an organization name.
  xml = import ./xml.nix { inherit lib; };
  element = name: value: optionalString (value != null) "  ${xml.element name value}";
  token = id: "@WAZUH_SECRET_${id}@";

  listener =
    l:
    "<remote>\n"
    + element "connection" l.connection
    + element "port" l.port
    + element "protocol" (concatStringsSep "," l.protocol)
    + element "ipv6" (yesNo (if l.ipv6 != null then l.ipv6 else l.connection == "secure" && cfg.listenIPv6))
    + element "local_ip" l.localIp
    + concatMapStrings (ip: element "allowed-ips" ip) l.allowedIps
    + concatMapStrings (ip: element "denied-ips" ip) l.deniedIps
    + element "queue_size" l.queueSize
    + "</remote>\n";

  # Attribute names sort, so the ids and the block order are stable.
  integrationSecrets = key: i: {
    hook = if i.hookUrlFile != null then "integration-${key}-hook_url" else null;
    key = if i.apiKeyFile != null then "integration-${key}-api_key" else null;
  };

  integration =
    key: i:
    let
      s = integrationSecrets key i;
    in
    "<integration>\n"
    + element "name" i.name
    + element "hook_url" (if s.hook != null then token s.hook else i.hookUrl)
    + element "api_key" (if s.key != null then token s.key else null)
    + element "level" i.level
    + optionalString (i.ruleIds != [ ]) (element "rule_id" (concatMapStringsSep "," toString i.ruleIds))
    + optionalString (i.groups != [ ]) (element "group" (concatStringsSep "," i.groups))
    + element "event_location" i.eventLocation
    + element "alert_format" i.alertFormat
    + element "max_log" i.maxLog
    + element "options" (if i.options == null then null else builtins.toJSON i.options)
    + element "timeout" i.timeout
    + element "retries" i.retries
    + "</integration>\n";

  githubTokenId = n: "github-api_auth-${toString n}-api_token";

  github =
    g:
    "<github>\n"
    + element "enabled" "yes"
    + element "interval" g.interval
    + element "time_delay" g.timeDelay
    + element "curl_max_size" g.curlMaxSize
    + element "only_future_events" (yesNo g.onlyFutureEvents)
    + concatMapStrings (x: x) (
      imap0 (
        n: a:
        "  <api_auth>\n"
        + "  ${element "org_name" a.orgName}"
        + "  ${element "api_token" (token (githubTokenId n))}"
        + "  </api_auth>\n"
      ) g.apiAuth
    )
    + "  <api_parameters>\n"
    + "  ${element "event_type" g.eventType}"
    + "  </api_parameters>\n"
    + "</github>\n";
in
{
  remote = concatMapStrings listener cfg.remote.listeners;

  integrations = concatMapStrings (x: x) (mapAttrsToList integration cfg.integrations);

  github = optionalString (cfg.github != null) (github cfg.github);

  # id -> { source; target = "argv" | "config"; }
  secrets =
    lib.listToAttrs (
      lib.concatLists (
        mapAttrsToList (
          key: i:
          let
            s = integrationSecrets key i;
          in
          lib.optional (s.hook != null) (lib.nameValuePair s.hook { source = i.hookUrlFile; target = "argv"; })
          ++ lib.optional (s.key != null) (lib.nameValuePair s.key { source = i.apiKeyFile; target = "argv"; })
        ) cfg.integrations
      )
      ++ lib.optionals (cfg.github != null) (
        imap0 (n: a: lib.nameValuePair (githubTokenId n) { source = a.apiTokenFile; target = "config"; }) cfg.github.apiAuth
      )
    );

  inherit token;
}
