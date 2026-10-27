# Writes the manager's ossec.conf.
#
# The block order follows WriteManager in src/init/inst-functions.sh at
# v4.14.8, and each block starts from the matching template under
# etc/templates/config/generic. Blocks that the module does not run are left
# out rather than disabled, except where a missing block means "enabled by
# default" to Wazuh. <indexer> and <vulnerability-detection> are the two
# cases: both default to enabled, so with no indexer they are written with
# <enabled>no</enabled>.
{
  cfg,
  pkgs,
  credentialPaths,
}:
let
  inherit (pkgs) lib;
  inherit (lib) concatMapStrings optionalString;

  yesNo = b: if b then "yes" else "no";

  global = ''
    <global>
      <jsonout_output>yes</jsonout_output>
      <alerts_log>yes</alerts_log>
      <logall>${yesNo cfg.logAll}</logall>
      <logall_json>${yesNo cfg.logAll}</logall_json>
      <email_notification>no</email_notification>
      <agents_disconnection_time>15m</agents_disconnection_time>
      <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
      <update_check>no</update_check>
    </global>
  '';

  alerts = ''
    <alerts>
      <log_alert_level>${toString cfg.alertLevel}</log_alert_level>
      <email_alert_level>12</email_alert_level>
    </alerts>
  '';

  logging = ''
    <logging>
      <log_format>plain</log_format>
    </logging>
  '';

  remote = ''
    <remote>
      <connection>secure</connection>
      <port>${toString cfg.remote.port}</port>
      <protocol>tcp</protocol>
      <queue_size>131072</queue_size>
    </remote>
  '';

  # The vulnerability scanner reads its feed into the indexer. Without an
  # indexer it has nowhere to write, so it is off.
  vulnerabilityDetection = ''
    <vulnerability-detection>
      <enabled>${yesNo (cfg.indexer != null)}</enabled>
      <index-status>yes</index-status>
      <feed-update-interval>60m</feed-update-interval>
    </vulnerability-detection>
  '';

  # The TLS paths point at the copies that setup-pre-wazuh-server installs
  # under etc/, not at the configured source paths. wazuh-modulesd reads them
  # as the wazuh user, and the source files can belong to root.
  indexer =
    if cfg.indexer == null then
      ''
        <indexer>
          <enabled>no</enabled>
        </indexer>
      ''
    else
      ''
        <indexer>
          <enabled>yes</enabled>
          <hosts>
        ${concatMapStrings (h: "      <host>${h}</host>\n") cfg.indexer.hosts}    </hosts>
          <ssl>
            <certificate_authorities>
              <ca>${credentialPaths.indexerCa}</ca>
            </certificate_authorities>
            <certificate>${credentialPaths.indexerCertificate}</certificate>
            <key>${credentialPaths.indexerKey}</key>
          </ssl>
        </indexer>
      '';

  ruleset = ''
    <ruleset>
      <!-- Default ruleset -->
      <decoder_dir>ruleset/decoders</decoder_dir>
      <rule_dir>ruleset/rules</rule_dir>
      <rule_exclude>0215-policy_rules.xml</rule_exclude>
      <list>etc/lists/audit-keys</list>
      <list>etc/lists/amazon/aws-eventnames</list>
      <list>etc/lists/security-eventchannel</list>
      <list>etc/lists/malicious-ioc/malware-hashes</list>
      <list>etc/lists/malicious-ioc/malicious-ip</list>
      <list>etc/lists/malicious-ioc/malicious-domains</list>

      <!-- User-defined ruleset -->
      <decoder_dir>etc/decoders</decoder_dir>
      <rule_dir>etc/rules</rule_dir>
    </ruleset>
  '';

  ruleTest = ''
    <rule_test>
      <enabled>yes</enabled>
      <threads>1</threads>
      <max_sessions>64</max_sessions>
      <session_timeout>15m</session_timeout>
    </rule_test>
  '';

  # ssl_manager_cert and ssl_manager_key are relative to /var/ossec. The
  # setup unit installs the configured pair there, or generates a
  # self-signed pair the way the upstream installer does.
  auth = ''
    <auth>
      <disabled>${yesNo (!cfg.auth.enable)}</disabled>
      <port>${toString cfg.auth.port}</port>
      <use_source_ip>no</use_source_ip>
      <purge>yes</purge>
      <use_password>${yesNo (cfg.auth.passwordFile != null)}</use_password>
      <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
      ${optionalString (cfg.auth.agentCa != null) "<ssl_agent_ca>${credentialPaths.authAgentCa}</ssl_agent_ca>"}
      <ssl_verify_host>no</ssl_verify_host>
      <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
      <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
      <ssl_auto_negotiate>no</ssl_auto_negotiate>
    </auth>
  '';

  # The manager monitors its own logs. The commands in the upstream
  # localfile-commands template (df, netstat, last) are left out: they need
  # tools that a NixOS host does not put on the daemon PATH by default.
  localfile = ''
    <localfile>
      <log_format>syslog</log_format>
      <location>/var/ossec/logs/active-responses.log</location>
    </localfile>
  '';
in
pkgs.writeText "ossec.conf" ''
  <ossec_config>
  ${global}
  ${alerts}
  ${logging}
  ${remote}
  ${vulnerabilityDetection}
  ${indexer}
  ${localfile}
  ${ruleset}
  ${ruleTest}
  ${auth}
  ${cfg.extraConfig}
  </ossec_config>
''
