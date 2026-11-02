# The ossec.conf blocks for the options in optional-services.nix.
# generate-server-config.nix merges `global` into the <global> defaults and
# appends `blocks`.
{
  cfg,
  pkgs,
}:
let
  inherit (pkgs) lib;
  # maild runs the smtp_server path with no arguments and writes the
  # message, headers included, to its standard input.
  sendmailWrapper = pkgs.writeShellScript "wazuh-maild-sendmail" ''
    exec ${cfg.email.sendmail} -t -i
  '';
  inherit (lib)
    concatMapStrings
    concatMapStringsSep
    concatStringsSep
    optionalAttrs
    ;
  xml = import ./xml.nix { inherit lib; };
  ids = list: if list == [ ] then null else concatMapStringsSep "," toString list;

  emailAlert =
    a:
    xml.element "email_alerts" {
      email_to = a.to;
      level = a.level;
      group = if a.groups == [ ] then null else concatStringsSep "|" a.groups;
      rule_id = ids a.ruleIds;
      event_location = a.eventLocation;
      format = a.format;
      do_not_delay = if a.doNotDelay then "" else null;
      do_not_group = if a.doNotGroup then "" else null;
    };

  report =
    r:
    xml.element "reports" {
      title = r.title;
      email_to = r.emailTo;
      group = r.group;
      category = r.category;
      rule = r.rule;
      level = r.level;
      location = r.location;
      srcip = r.srcip;
      user = r.user;
      showlogs = r.showLogs;
    };

  syslogOutput =
    s:
    xml.element "syslog_output" {
      server = s.server;
      port = s.port;
      level = s.level;
      group = s.group;
      rule_id = ids s.ruleIds;
      location = s.location;
      use_fqdn = s.useFqdn;
      format = s.format;
    };

  agentless =
    c:
    xml.element "agentless" {
      type = c.type;
      frequency = c.frequency;
      host = c.hosts;
      state = c.state;
      arguments = c.arguments;
    };

  clusterKeyId = "cluster-key";
  cluster =
    c:
    xml.element "cluster" {
      name = c.name;
      node_name = c.nodeName;
      node_type = c.nodeType;
      key = "@WAZUH_SECRET_${clusterKeyId}@";
      port = c.port;
      bind_addr = c.bindAddr;
      nodes.node = c.nodes;
      hidden = c.hidden;
      disabled = false;
    };
in
{
  # Merged into the <global> defaults, below the settings option.
  global = optionalAttrs cfg.email.enable {
    email_notification = true;
    smtp_server = if cfg.email.sendmail != null then "${sendmailWrapper}" else cfg.email.smtpServer;
    email_from = cfg.email.from;
    email_to = cfg.email.to;
    email_reply_to = cfg.email.replyTo;
    helo_server = cfg.email.heloServer;
    email_maxperhour = cfg.email.maxPerHour;
    email_idsname = cfg.email.idsName;
    email_log_source = cfg.email.logSource;
  };

  blocks =
    concatMapStrings emailAlert cfg.emailAlerts
    + concatMapStrings report cfg.reports
    + concatMapStrings syslogOutput cfg.syslogOutput
    + concatMapStrings agentless cfg.agentless.checks
    + lib.optionalString (cfg.cluster != null) (cluster cfg.cluster);

  # id -> { source; target; pattern; }, as in runtime-config.nix. pattern
  # is an extended regular expression that the whole value must match.
  # wazuh-clusterd refuses a key that is not 32 letters and digits
  # (framework/wazuh/core/cluster/cluster.py, check_cluster_config).
  secrets = optionalAttrs (cfg.cluster != null) {
    ${clusterKeyId} = {
      source = cfg.cluster.keyFile;
      target = "config";
      pattern = "[A-Za-z0-9]{32}";
    };
  };
}
