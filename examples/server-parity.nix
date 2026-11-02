# Import this alongside the flake's nixosModules.wazuh-server.
# Provision the /run/keys files with your secret manager before starting.
{ pkgs, ... }:
{
  services.wazuh-server = {
    enable = true;
    openFirewall = true;
    remote.listeners = [
      {
        connection = "secure";
        port = 1514;
        protocol = [ "tcp" ];
        queueSize = 131072;
      }
      {
        connection = "syslog";
        port = 514;
        protocol = [ "udp" ];
        allowedIps = [ "0.0.0.0/0" ];
      }
    ];
    auth = {
      enable = true;
      port = 1515;
      passwordFile = "/run/keys/wazuh-enrollment";
      tls = {
        certificate = "/run/keys/sslmanager.cert";
        key = "/run/keys/sslmanager.key";
      };
    };
    api.users = {
      wazuh.passwordFile = "/run/keys/wazuh-api-password";
      wazuh-wui.passwordFile = "/run/keys/wazuh-wui-password";
    };
    indexer = {
      hosts = [ "https://127.0.0.1:9200" ];
      tls = {
        ca = "/run/keys/root-ca.pem";
        certificate = "/run/keys/filebeat.pem";
        key = "/run/keys/filebeat-key.pem";
      };
      usernameFile = "/run/keys/indexer-username";
      passwordFile = "/run/keys/indexer-password";
    };
    integrations = {
      virustotal = {
        apiKeyFile = "/run/keys/virustotal-api-key";
        groups = [ "syscheck" ];
        alertFormat = "json";
      };
      slack = {
        hookUrlFile = "/run/keys/slack-webhook";
        alertFormat = "json";
        level = 11;
      };
    };
    github = {
      interval = "1m";
      timeDelay = "1m";
      curlMaxSize = "1M";
      onlyFutureEvents = false;
      apiAuth = [
        {
          orgName = "xnor-software";
          apiTokenFile = "/run/keys/github-token";
        }
      ];
      eventType = "all";
    };
    path = [
      pkgs.coreutils
      pkgs.nettools
      pkgs.gnused
      pkgs.util-linux
      pkgs.last
    ];
    settings = (import ./server/monitoring.nix) // {
      localfile = [
        {
          log_format = "command";
          command = "df -P";
          frequency = 360;
        }
        {
          log_format = "full_command";
          command = ''netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d'';
          alias = "netstat listening ports";
          frequency = 360;
        }
        {
          log_format = "full_command";
          command = "last -n 20";
          frequency = 360;
        }
        {
          log_format = "syslog";
          location = "/var/ossec/logs/active-responses.log";
        }
        # NixOS logs through journald instead of Debian's /var/log files.
        {
          log_format = "journald";
          location = "journald";
        }
      ];
    };
  };
  # logcollector runs as wazuh; journal access needs the journal group.
  users.users.wazuh.extraGroups = [ "systemd-journal" ];
}
