# Inventory of negative module assertion cases. Each case names its diagnostic;
# an unrelated failed assertion must not satisfy it.
let
  syslog = {
    connection = "syslog";
    port = 514;
    protocol = [ "udp" ];
    allowedIps = [ "127.0.0.1" ];
  };
  cluster = {
    nodeName = "test";
    nodeType = "master";
    keyFile = "/run/key";
    nodes = [ "192.0.2.1" ];
  };
  helper = {
    address = "192.0.2.2";
    user = "test";
    passwordFile = "/run/password";
  };
  check = {
    type = "ssh_generic_diff";
    hosts = [ "test@192.0.2.1" ];
    frequency = 60;
    state = "periodic_diff";
  };
  case = diagnostic: options: { inherit diagnostic options; };
in
[
  (case "cannot be enabled on the same host" { _agent = true; })
  (case "integrationScripts keys must" { integrationScripts.bad = "/run/custom-script"; })
  (case "Each custom integration needs" { integrations.test.name = "custom-missing"; })
  (case "RIDS timing and allowHigherVersions" {
    remote.listeners = [ (syslog // { ridsClosingTime = "5s"; }) ];
  })
  (case "at most one secure listener" {
    remote.listeners = [
      {
        connection = "secure";
        port = 1514;
      }
      {
        connection = "secure";
        port = 1517;
      }
    ];
  })
  (case "only a secure listener can use tcp and udp" {
    remote.listeners = [
      (
        syslog
        // {
          protocol = [
            "tcp"
            "udp"
          ];
        }
      )
    ];
  })
  (case "queueSize applies" { remote.listeners = [ (syslog // { queueSize = 100; }) ]; })
  (case "a syslog listener needs allowedIps" {
    remote.listeners = [ (syslog // { allowedIps = [ ]; }) ];
  })
  (case "two listeners use the same port" {
    remote.listeners = [
      syslog
      syslog
    ];
  })
  (case "set remote.listeners or remote.port" {
    remote.port = 1514;
    remote.listeners = [ syslog ];
  })
  (case "use only letters, digits" {
    integrations."bad name" = {
      name = "slack";
      hookUrl = "http://localhost";
    };
  })
  (case "set hookUrl or hookUrlFile" {
    integrations.test = {
      name = "slack";
      hookUrl = "http://localhost";
      hookUrlFile = "/run/hook";
    };
  })
  (case "slack needs hookUrl or hookUrlFile" { integrations.test.name = "slack"; })
  (case "virustotal needs apiKeyFile" { integrations.test.name = "virustotal"; })
  (case "secretFiles and credentialFiles names" { secretFiles."bad name" = "/run/secret"; })
  (case "auth dedicated" { auth.settings.port = 1515; })
  (case "settings supports only" { settings.remote.port = 1514; })
  (case "email.enable to run maild" { settings.global.email_notification = true; })
  (case "raw settings.cluster must have disabled" { settings.cluster.disabled = false; })
  (case "requires activeResponse.enable" {
    activeResponse.enable = false;
    settings.active-response = [ ];
  })
  (case "vulnerability detection requires" { settings.vulnerability-detection.enabled = true; })
  (case "set exactly one of smtpServer and sendmail" {
    email = {
      enable = true;
      from = "test@example.com";
      to = [ "test@example.com" ];
    };
  })
  (case "emailAlerts and reports need email.enable" {
    reports = [ { emailTo = [ "test@example.com" ]; } ];
  })
  (case "every host in checks needs" {
    agentless = {
      checks = [ check ];
      knownHosts = "test";
    };
  })
  (case "knownHosts must list" {
    agentless = {
      checks = [ check ];
      credentials."test@192.0.2.1".passwordFile = "/run/password";
    };
  })
  (case "a credential without passwordFile needs" { agentless.credentials."test@192.0.2.1" = { }; })
  (case "set cluster or settings.cluster" {
    inherit cluster;
    settings.cluster.disabled = true;
  })
  (case "localhost, NODE_IP" {
    cluster = cluster // {
      nodes = [ "localhost" ];
    };
  })
  (case "only the master runs the helper" {
    cluster = cluster // {
      nodeType = "worker";
      haproxyHelper = helper;
    };
  })
  (case "https needs caFile" {
    cluster = cluster // {
      haproxyHelper = helper // {
        protocol = "https";
      };
    };
  })
  (case "set clientCertFile and clientKeyFile together" {
    cluster = cluster // {
      haproxyHelper = helper // {
        clientCertFile = "/run/cert";
      };
    };
  })
  (case "database_output was removed" { extraConfig = "<database_output/>"; })
  (case "filebeat.archives needs" {
    filebeat.archives = true;
    indexer = {
      hosts = [ "https://localhost:9200" ];
      usernameFile = "/run/user";
      passwordFile = "/run/pass";
      tls = {
        ca = "/run/ca";
        certificate = "/run/cert";
        key = "/run/key";
      };
    };
  })
  (case "accepts only the built-in users" { api.users.unknown.passwordFile = "/run/password"; })
  (case "a file name may contain only" { ruleset.rules."../escape.xml".text = "x"; })
  (case "a file name may contain only" { ruleset.lists.".hidden".text = "x"; })
  (case "must end in .xml" { ruleset.rules."local_rules".text = "x"; })
  (case "must end in .xml" { ruleset.decoders."local_decoder.txt".text = "x"; })
  (case "a name cannot end in .cdb" { ruleset.lists."users.cdb".text = "x"; })
  (case "set exactly one of text and source" { ruleset.rules."local_rules.xml" = { }; })
  (case "set exactly one of text and source" {
    ruleset.lists.users = {
      text = "x";
      source = "/run/users";
    };
  })
]
