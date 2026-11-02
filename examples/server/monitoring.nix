# Non-secret monitoring settings from the upstream manager configuration.
# Used by server-parity.nix and by the server-config VM check.
{
  global = {
    jsonout_output = true;
    alerts_log = true;
    logall = false;
    logall_json = false;
    email_notification = false;
    smtp_server = "smtp.example.wazuh.com";
    email_from = "wazuh@example.wazuh.com";
    email_to = "recipient@example.wazuh.com";
    email_maxperhour = 12;
    email_log_source = "alerts.log";
    agents_disconnection_time = "10m";
    agents_disconnection_alert_time = 0;
    white_list = [
      "127.0.0.1"
      "^localhost.localdomain$"
      "127.0.0.53"
    ];
  };
  alerts = {
    log_alert_level = 3;
    email_alert_level = 12;
  };
  logging.log_format = "plain";
  rootcheck = {
    disabled = false;
    check_files = true;
    check_trojans = true;
    check_dev = true;
    check_sys = true;
    check_pids = true;
    check_ports = true;
    check_if = true;
    frequency = 43200;
    rootkit_files = "etc/rootcheck/rootkit_files.txt";
    rootkit_trojans = "etc/rootcheck/rootkit_trojans.txt";
    skip_nfs = true;
  };
  wodle = [
    {
      _attributes.name = "cis-cat";
      disabled = true;
      timeout = 1800;
      interval = "1d";
      scan-on-start = true;
      java_path = "wodles/java";
      ciscat_path = "wodles/ciscat";
    }
    {
      _attributes.name = "osquery";
      disabled = true;
      run_daemon = true;
      log_path = "/var/log/osquery/osqueryd.results.log";
      config_path = "/etc/osquery/osquery.conf";
      add_labels = true;
    }
    {
      _attributes.name = "syscollector";
      disabled = false;
      interval = "1h";
      scan_on_start = true;
      hardware = true;
      os = true;
      network = true;
      packages = true;
      ports = {
        _attributes.all = false;
        _text = true;
      };
      processes = true;
      synchronization.max_eps = 10;
    }
  ];
  sca = {
    enabled = true;
    scan_on_start = true;
    interval = "12h";
    skip_nfs = true;
  };
  syscheck = {
    disabled = false;
    frequency = 43200;
    scan_on_start = true;
    alert_new_files = true;
    auto_ignore = {
      _attributes = {
        frequency = 10;
        timeframe = 3600;
      };
      _text = false;
    };
    # NixOS executables are in immutable store paths. Monitor the system
    # selection plus host configuration instead of Debian's /usr and /sbin.
    directories = [
      "/etc"
      "/run/current-system"
      "/boot"
    ];
    ignore = [
      "/etc/mtab"
      "/etc/hosts.deny"
      "/etc/mail/statistics"
      "/etc/random-seed"
      "/etc/random.seed"
      "/etc/adjtime"
      "/etc/httpd/logs"
      "/etc/utmpx"
      "/etc/wtmpx"
      "/etc/cups/certs"
      "/etc/dumpdates"
      "/etc/svc/volatile"
      {
        _attributes.type = "sregex";
        _text = ".log$|.swp$";
      }
    ];
    nodiff = "/etc/ssl/private.key";
    skip_nfs = true;
    skip_dev = true;
    skip_proc = true;
    skip_sys = true;
    process_priority = 10;
    max_eps = 50;
    synchronization = {
      enabled = true;
      interval = "5m";
      max_eps = 10;
    };
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
    ];
  };
  rule_test = {
    enabled = true;
    threads = 1;
    max_sessions = 64;
    session_timeout = "15m";
  };
  cluster = {
    name = "wazuh";
    node_name = "node01";
    node_type = "master";
    key = "";
    port = 1516;
    bind_addr = "0.0.0.0";
    nodes.node = "NODE_IP";
    hidden = false;
    disabled = true;
  };
}
