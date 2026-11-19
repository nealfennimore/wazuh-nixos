# Run the Wazuh server on NixOS

The server is the Wazuh manager: it enrolls agents, receives their events,
applies the ruleset and writes alerts. This module runs the manager daemons
and the Wazuh API on one host, and generates `ossec.conf` and `api.yaml` from
its options. With `indexer` set, it also ships alerts to a Wazuh indexer.

The module cannot share a host with `services.wazuh-agent`. Both modules own
`/var/ossec` and the `wazuh` account. The manager monitors its own host.

Related guides:

- [Agent guide](../wazuh-agent/README.md): the hosts that report to this server.
- [Indexer guide](../wazuh-indexer/README.md): the store for alerts and inventory.
- [Dashboard guide](../wazuh-dashboard/README.md): the browser UI, which reads this server's API.
- [Server package](../../pkgs/wazuh-server/README.md): how the manager and API are built.
- [Manager configuration coverage](../../docs/manager-reference.md): the upstream reference sections and the option that covers each one.

## Add the module to a host

Add the flake as an input, as in the [agent guide](../wazuh-agent/README.md#add-the-agent-to-a-nixos-host),
then import the server module and set the secrets.

```nix
{
  imports = [ inputs.wazuh.nixosModules.wazuh-server ];
  services.wazuh-server = {
    enable = true;
    openFirewall = true;
    auth.passwordFile = "/run/secrets/wazuh-authd-pass";
    api.tls = {
      certificate = "/run/secrets/wazuh-api.crt";
      key = "/run/secrets/wazuh-api.key";
    };
  };
}
```

The module writes `ossec.conf` and `api.yaml` from its options. `extraConfig`
appends XML inside `<ossec_config>`. Without `api.tls`, the API generates a
self-signed pair on first start. Without `auth.tls`, the enrollment service
generates one self-signed pair and keeps it.

The API starts with the upstream default users `wazuh` and `wazuh-wui`, and
the default password of each user is its name. `api.users.<name>.passwordFile`
replaces that password with the content of a file.

```nix
services.wazuh-server.api.users = {
  wazuh.passwordFile = "/run/secrets/wazuh-api-wazuh";
  wazuh-wui.passwordFile = "/run/secrets/wazuh-api-wui";
};
```

PID 1 reads the files through `LoadCredential`, so they can belong to root.
The API requires 8 to 64 characters with an upper-case letter, a lower-case
letter, a digit and a symbol. The unit `wazuh-api-users.service` runs after
`wazuh-apid.service`. It waits for the API, then it tries each user's
configured password. If the configured password authenticates, the unit
changes nothing. Otherwise it authenticates with the previous password and
sets the new password through `PUT /security/users/{id}`. If neither
password authenticates, the unit fails and names the user. Put the current
password in `defaultPasswordFile`, or reset the password through the API. Without
`api.users`, the upstream defaults stay.

The previous password is the upstream default, the user name, unless
`api.users.<name>.defaultPasswordFile` names a file. PID 1 reads that file
through `LoadCredential` too. No password is an argument of a process that
the unit starts, because every local user can read `/proc/<pid>/cmdline`.

When `wazuh-api-users.service` fails, `wazuh-apid-guard.service` starts. The
guard waits for the API and authenticates each configured user with the
upstream default password. If one of them authenticates, the guard stops
`wazuh-apid.service` and fails, so `systemctl --failed` shows the condition.
A host whose first provisioning failed then has no listening API. If no
default authenticates, the guard leaves the API up. To recover, fix the
password files and restart `wazuh-api-users.service`. The restart starts
the API again.

With `api.tls` set, the unit verifies the API certificate and connects to
`api.serverName`, which defaults to the host name. The host name must be a
name in the certificate. Without `api.tls`, the unit connects to `127.0.0.1`
with certificate verification off, because the self-signed pair that the API
generates carries no usable name. The password then still travels encrypted,
but the peer is not authenticated.

`activeResponse.enable` defaults to `true`, as upstream. The module runs
`wazuh-execd` as `wazuh` with no capability and writes the upstream default
`<command>` definitions to `ossec.conf`, except `restart-wazuh`, whose program
the package removes. No `<active-response>` block is written, so no response
runs on the manager until `extraConfig` adds one. The stock response programs
need more than the unit grants: `firewall-drop` and `route-null` need
`CAP_NET_ADMIN`, `host-deny` writes `/etc/hosts.deny`, and `disable-account`
needs root. Grant those to the unit before you bind such a response to the
manager. `false` removes the unit and writes
`<active-response><disabled>yes</disabled></active-response>`.

Four daemons chroot into `/var/ossec` as upstream does: analysisd, remoted,
monitord and wazuh-db. Their units carry `CAP_SYS_CHROOT` and nothing else.
The other units carry no capability. Each daemon runs as `wazuh` with
`ProtectSystem=strict` and a writable bind on its state directories only.

```sh
nix build .#checks.x86_64-linux.server
```

The check boots one VM, waits for every unit, confirms the four chroots and
the ports, loads the ruleset with `wazuh-analysisd -t`, confirms that
`wazuh-api-users.service` replaced the default passwords, that no password was
a process argument (kernel audit), that `defaultPasswordFile` works, that the
guard stops a fresh API whose provisioning failed, and authenticates
against the API with the test PKI.

`listenIPv6` (default `true`) binds remoted and authd to a dual-stack socket.
An agent that names the manager by hostname can resolve an IPv6 address first.
With the upstream IPv4-only binding that agent cannot connect.

## Options

Every option lives under `services.wazuh-server`. Paths point outside the Nix
store unless the row says otherwise. PID 1 reads each `*File` option through
`LoadCredential`, so those files can be root-only.

| Option | Default | Purpose |
|--------|---------|---------|
| `enable` | `false` | Runs the manager daemons and the API. |
| `package` | `pkgs.wazuh-server` | The server package. |
| `openFirewall` | `false` | Opens the agent, enrollment and API ports in the firewall. |
| `remote.port` | `1514` | The TCP port of the default secure listener. Set `remote.port` or `remote.listeners`, not both. |
| `remote.listeners` | one secure TCP listener on `remote.port` | The `remoted` listeners, one `<remote>` block each. At most one listener can be secure. |
| `remote.listeners.*.connection` | none | `secure` for agents, `syslog` for syslog senders. |
| `remote.listeners.*.port` | none | The port the listener binds. A port below 1024 gives `wazuh-remoted` `CAP_NET_BIND_SERVICE`. |
| `remote.listeners.*.protocol` | `[ "tcp" ]` | `tcp`, `udp`, or both. Only a secure listener can use both. |
| `remote.listeners.*.localIp` | `null` | The address the listener binds. `null` binds every address. |
| `remote.listeners.*.ipv6` | `null` | Binds an IPv6 socket. `null` follows `listenIPv6` for a secure listener and binds IPv4 for a syslog listener. |
| `remote.listeners.*.allowedIps` | `[ ]` | Syslog senders that `remoted` accepts, as addresses or networks. A syslog listener needs one entry at least. |
| `remote.listeners.*.deniedIps` | `[ ]` | Syslog senders that `remoted` refuses. |
| `remote.listeners.*.queueSize` | `null` | The message queue size of a secure listener. `null` keeps the Wazuh default. |
| `listenIPv6` | `true` | Binds `remoted` and `authd` to a dual-stack socket. Off, both bind IPv4 only, as upstream does. |
| `auth.enable` | `true` | Runs `wazuh-authd`, the enrollment service. |
| `auth.port` | `1515` | The enrollment port. |
| `auth.passwordFile` | `null` | File with the enrollment password. `null` disables password enrollment. |
| `auth.tls` | `null` | The certificate `authd` presents. `null` generates a self-signed pair once, as the upstream installer does. |
| `auth.tls.certificate` | none | The certificate file. |
| `auth.tls.key` | none | Its private key. |
| `auth.agentCa` | `null` | CA that enrolling agents must present a certificate from. `null` accepts any agent. |
| `api.port` | `55000` | The API port (HTTPS). |
| `api.listenAddresses` | `[ "0.0.0.0" "::" ]` | Addresses the API binds. |
| `api.tls` | `null` | The API certificate. `null` makes the API generate a self-signed pair on first start. |
| `api.tls.certificate` | none | The certificate file. |
| `api.tls.key` | none | Its private key. |
| `api.serverName` | the host name, or `127.0.0.1` without `api.tls` | The name `wazuh-api-users.service` connects to. With `api.tls` it must appear in the certificate. |
| `api.logLevel` | `"info"` | The API log level: `debug2`, `debug`, `info`, `warning`, `error` or `critical`. |
| `api.settings` | `{ }` | Extra `api.yaml` settings, merged over the generated ones. |
| `api.users` | `{ }` | Passwords for the built-in users `wazuh` and `wazuh-wui`, set after the API starts. Without an entry the upstream default stays. |
| `api.users.<name>.passwordFile` | none | File with the password this user must have. The API requires 8 to 64 characters with upper, lower, digit and symbol. |
| `api.users.<name>.defaultPasswordFile` | none | File with the password the user has before this module changes it. Read through `LoadCredential`. Without it the upstream default applies, which is the user name. Used only when `passwordFile` does not authenticate. |
| `activeResponse.enable` | `true` | Runs `wazuh-execd` as `wazuh` and writes the upstream default `<command>` definitions. No `<active-response>` block is written, so no response runs until `extraConfig` adds one. |
| `indexer` | `null` | The indexer connection. It drives the `<indexer>` block, the keystore entries and the filebeat output. `null` disables all three and vulnerability detection. |
| `indexer.hosts` | `[ ]` | Indexer URLs, for example `https://indexer:9200`. |
| `indexer.tls.ca` | none | CA the indexer certificates chain to. |
| `indexer.tls.certificate` | none | Client certificate for the indexer. |
| `indexer.tls.key` | none | Its private key. |
| `indexer.usernameFile` | none | File with the indexer user name, one line. Written to the Wazuh keystore. |
| `indexer.passwordFile` | none | File with that user's password, one line. Written to the Wazuh keystore. |
| `filebeat.enable` | `true` | Ships alerts to the indexer with filebeat. Takes effect only when `indexer` is set. |
| `filebeat.package` | `pkgs/filebeat-oss` | The filebeat package. The default is filebeat OSS 7.10.2, the version upstream ships. |
| `filebeat.archives` | `false` | Also ships `logs/archives/archives.json` into `wazuh-archives-4.x-*`. Needs `logAll`. |
| `filebeat.settings` | `{ }` | Extra `filebeat.yml` settings, merged over the generated ones. Dotted keys are accepted. |
| `logAll` | `false` | Archives every event, not only alerts, under `logs/archives`. |
| `alertLevel` | `3` | The minimum rule level that produces an alert. |
| `integrations` | `{ }` | Integrations, one `<integration>` block each. A non-empty set runs `wazuh-integratord`. |
| `integrations.<name>.name` | the attribute name | The integration program: `slack`, `virustotal`, `pagerduty`, `shuffle` or `maltiverse`. |
| `integrations.<name>.hookUrl` | `null` | A webhook URL that is not a secret. The value goes into the Nix store. |
| `integrations.<name>.hookUrlFile` | `null` | File with the webhook URL, one line. |
| `integrations.<name>.apiKeyFile` | `null` | File with the API key, one line. |
| `integrations.<name>.level` | `null` | The minimum alert level that the integration receives. |
| `integrations.<name>.ruleIds` | `[ ]` | Rule IDs that the integration receives. Empty means every rule. |
| `integrations.<name>.groups` | `[ ]` | Rule groups that the integration receives. Empty means every group. |
| `integrations.<name>.eventLocation` | `null` | A regular expression for the alert location. |
| `integrations.<name>.alertFormat` | `"json"` | The alert format. The packaged integrations read JSON only. |
| `integrations.<name>.maxLog` | `null` | The maximum length of the log text sent to the integration. |
| `integrations.<name>.options` | `null` | A JSON object that the integration receives as its options file. |
| `integrations.<name>.timeout` | `null` | Seconds before a request of the integration times out. |
| `integrations.<name>.retries` | `null` | The number of retries after a failed request. |
| `github` | `null` | The GitHub audit-log module of `wazuh-modulesd`. `null` leaves it out. |
| `github.apiAuth` | none | The organizations to read, one entry each. |
| `github.apiAuth.*.orgName` | none | The GitHub organization. |
| `github.apiAuth.*.apiTokenFile` | none | File with a token that can read the audit log of the organization, one line. |
| `github.interval` | `"1m"` | The time between two reads of the audit log. |
| `github.timeDelay` | `"30s"` | The delay that GitHub needs to publish an event. |
| `github.curlMaxSize` | `"1M"` | The maximum size of one API response. |
| `github.onlyFutureEvents` | `true` | Reads only events after the first start. `false` also reads the existing log. |
| `github.eventType` | `"all"` | The event types to read: `all`, `git` or `web`. |
| `settings` | `{ }` | Structured XML sections merged over generated defaults; lists replace repeated elements. See the structured configuration example below. |
| `email.enable` | `false` | Runs `wazuh-maild` and turns on `email_notification`. |
| `email.smtpServer` | `null` | The SMTP relay that `maild` connects to on port 25. `maild` has no SMTP authentication and no TLS. Set `smtpServer` or `sendmail`, not both. |
| `email.sendmail` | `null` | A sendmail-compatible program, for example `msmtp`. The module runs it as `sendmail -t -i`. It must work without setuid. |
| `email.from` | none | The sender address. |
| `email.to` | none | The default recipients. |
| `email.replyTo` | `null` | The Reply-To address. |
| `email.heloServer` | `null` | The name that `maild` sends in HELO. |
| `email.maxPerHour` | `12` | The maximum number of messages per hour. |
| `email.idsName` | `null` | The manager name in the message header. |
| `email.logSource` | `"alerts.log"` | The alert file that `maild` reads: `alerts.log` or `alerts.json`. |
| `emailAlerts` | `[ ]` | Extra recipients for selected alerts, one `<email_alerts>` block each. Needs `email.enable`. |
| `emailAlerts.*.to` | none | The recipients. |
| `emailAlerts.*.level` | `null` | The minimum alert level. |
| `emailAlerts.*.groups` | `[ ]` | Rule groups. Empty means every group. |
| `emailAlerts.*.ruleIds` | `[ ]` | Rule IDs. Empty means every rule. |
| `emailAlerts.*.eventLocation` | `null` | The alert location. |
| `emailAlerts.*.format` | `"full"` | `full` or `sms`. |
| `emailAlerts.*.doNotDelay` | `false` | Sends each alert at once. |
| `emailAlerts.*.doNotGroup` | `false` | Sends each alert in its own message. |
| `reports` | `[ ]` | Daily reports that `wazuh-monitord` mails, one `<reports>` block each. Needs `email.enable`. |
| `reports.*.title` | `null` | The subject of the report. |
| `reports.*.emailTo` | none | The recipients. |
| `reports.*.group` | `null` | The rule group to report on. |
| `reports.*.category` | `null` | The rule category to report on. |
| `reports.*.rule` | `null` | The rule ID to report on. |
| `reports.*.level` | `null` | The minimum alert level to report on. |
| `reports.*.location` | `null` | The alert location to report on. |
| `reports.*.srcip` | `null` | The source address to report on. |
| `reports.*.user` | `null` | The user name to report on. |
| `reports.*.showLogs` | `false` | Includes the logs in the report. |
| `agentless.checks` | `[ ]` | Agentless checks, one `<agentless>` block each. A non-empty list runs `wazuh-agentlessd`. |
| `agentless.checks.*.type` | none | The script under `agentless/`, for example `ssh_integrity_check_linux` or `ssh_generic_diff`. |
| `agentless.checks.*.hosts` | none | Devices as `user@host`. Each one needs an entry in `agentless.credentials`. |
| `agentless.checks.*.frequency` | none | Seconds between two checks. |
| `agentless.checks.*.state` | none | `periodic` analyzes the output like a log. `periodic_diff` alerts when the output changes. |
| `agentless.checks.*.arguments` | `null` | Directories for the integrity checks, or the commands for `ssh_generic_diff`. |
| `agentless.credentials` | `{ }` | Login data per `user@host`, written to `agentless/.passlist`. |
| `agentless.credentials.<name>.passwordFile` | `null` | File with the SSH password, one line. `null` logs in with `agentless.sshKeyFile`. |
| `agentless.credentials.<name>.additionalPasswordFile` | `null` | File with the `su` password, one line. |
| `agentless.sshKeyFile` | `null` | The private SSH key for devices without a password. It is installed for the `wazuh` user. |
| `agentless.knownHosts` | `""` | `known_hosts` lines for every device. A device whose key is not listed is refused. |
| `cluster` | `null` | The manager cluster. A value runs `wazuh-clusterd`. |
| `cluster.name` | `"wazuh"` | The cluster name. Every node uses the same one. |
| `cluster.nodeName` | none | The name of this node. |
| `cluster.nodeType` | none | `master` or `worker`. |
| `cluster.keyFile` | none | File with the cluster key: 32 letters and digits, the same on every node. |
| `cluster.port` | `1516` | The TCP port of the master. |
| `cluster.bindAddr` | `"0.0.0.0"` | The address that the master listens on. |
| `cluster.nodes` | none | The address of the master. Workers connect to the first entry. |
| `cluster.hidden` | `false` | Leaves the cluster information out of alerts. |
| `cluster.haproxyHelper` | `null` | The HAProxy helper of the master, which balances agents across the nodes. |
| `cluster.haproxyHelper.enable` | `true` | Runs the helper. `false` writes `haproxy_disabled` as `yes`. |
| `cluster.haproxyHelper.address` | none | The address of the HAProxy Data Plane API. |
| `cluster.haproxyHelper.port` | `5555` | The port of the Data Plane API, 1024 to 65535. |
| `cluster.haproxyHelper.protocol` | `"http"` | `http` or `https`. `https` needs `caFile`. |
| `cluster.haproxyHelper.user` | none | The Data Plane API user. |
| `cluster.haproxyHelper.passwordFile` | none | File with the Data Plane API password, one line without a comma. |
| `cluster.haproxyHelper.backend` | `"wazuh_reporting"` | The HAProxy backend that the helper manages. |
| `cluster.haproxyHelper.resolver` | `null` | The HAProxy resolver for the backend servers. |
| `cluster.haproxyHelper.caFile` | `null` | The CA certificate of the Data Plane API. |
| `cluster.haproxyHelper.clientCertFile` | `null` | The client certificate. Set it together with `clientKeyFile`. |
| `cluster.haproxyHelper.clientKeyFile` | `null` | The client key. |
| `cluster.haproxyHelper.clientKeyPasswordFile` | `null` | File with the password of the client key, one line without a comma. |
| `cluster.haproxyHelper.excludedNodes` | `[ ]` | Nodes that receive no agents. |
| `cluster.haproxyHelper.frequency` | `null` | Seconds between two balance checks, 10 or more. |
| `cluster.haproxyHelper.agentChunkSize` | `null` | Agents moved per step, 100 or more. |
| `cluster.haproxyHelper.agentReconnectionTime` | `null` | Seconds between two reconnection steps. |
| `cluster.haproxyHelper.agentReconnectionStabilityTime` | `null` | Seconds the cluster must be stable before agents move, 10 or more. |
| `cluster.haproxyHelper.imbalanceTolerance` | `null` | The tolerated imbalance, a decimal above 0 and at most 1. |
| `cluster.haproxyHelper.removeDisconnectedNodeAfter` | `null` | Minutes before a disconnected node leaves the backend. |
| `syslogOutput` | `[ ]` | Syslog servers that receive alerts, one `<syslog_output>` block each. A non-empty list runs `wazuh-csyslogd`. |
| `syslogOutput.*.server` | none | The address or host name of the syslog server. |
| `syslogOutput.*.port` | `514` | The UDP port. |
| `syslogOutput.*.level` | `null` | The minimum alert level. |
| `syslogOutput.*.group` | `null` | The rule group. Separate several groups with `\|`. |
| `syslogOutput.*.ruleIds` | `[ ]` | Rule IDs. Empty means every rule. |
| `syslogOutput.*.location` | `null` | The alert location. |
| `syslogOutput.*.useFqdn` | `false` | Sends the full host name. |
| `syslogOutput.*.format` | `"default"` | `default`, `cef`, `splunk` or `json`. |
| `extraConfig` | `""` | XML appended inside `<ossec_config>`. |
| `path` | `[ ]` | Packages added to the daemons' PATH, for command readers and integrations. |
| `ruleset.rules.<name>.text` | `null` | Content of the rule file `<name>`. The name must end in `.xml`. Set `text` or `source`. |
| `ruleset.rules.<name>.source` | `null` | File with the content of the rule file. A Nix path literal goes to the store at build time. A string names a host file that the setup unit reads at each activation. |
| `ruleset.decoders.<name>.text` | `null` | Content of the decoder file `<name>`. The name must end in `.xml`. Set `text` or `source`. |
| `ruleset.decoders.<name>.source` | `null` | File with the content of the decoder file. Same rules as for a rule file. |
| `ruleset.lists.<name>.text` | `null` | Content of the CDB list `<name>`, one `key:value` on each line. The name must not end in `.cdb`. Set `text` or `source`. |
| `ruleset.lists.<name>.source` | `null` | File with the content of the CDB list. Same rules as for a rule file. |
| `ruleset.validate` | `true` | Loads the declared files with `wazuh-analysisd -t` at build time. An error or a warning fails the build. |

## Receive syslog, run integrations and read GitHub

`remote.listeners` replaces the single agent listener with a list. The
example below keeps the agent listener and adds a syslog listener on
514/udp. Port 514 is below 1024, so `wazuh-remoted` gets
`CAP_NET_BIND_SERVICE`. With `openFirewall`, the module opens each listener
port for its protocols.

A syslog listener binds IPv4 unless its `ipv6` is set. Point each syslog
sender at the IPv4 address of the server. If a sender resolves the server
name to an IPv6 address first, its messages go to a port with no listener.
UDP reports no error for that, so the messages are lost without a warning.

```nix
services.wazuh-server = {
  remote.listeners = [
    { connection = "secure"; port = 1514; protocol = [ "tcp" ]; queueSize = 131072; }
    { connection = "syslog"; port = 514; protocol = [ "udp" ]; allowedIps = [ "192.168.1.0/24" ]; }
  ];
  integrations.virustotal = { apiKeyFile = "/run/secrets/wazuh-virustotal-key"; groups = [ "syscheck" ]; };
  integrations.slack = { hookUrlFile = "/run/secrets/wazuh-slack-hook"; level = 11; };
  github.apiAuth = [ { orgName = "example-org"; apiTokenFile = "/run/secrets/wazuh-github-token"; } ];
};
```

`remoted` starts one child process for each listener. With more than one
listener, systemd has no single main process to supervise. The unit stays
active while one child runs, and systemd restarts it when the last child
exits. If one listener stops while another runs, systemd does not restart
it. The upstream `wazuh-control` behaves the same way.

The module reads secret-file contents only at runtime. Use quoted runtime
paths (for example `"/run/keys/slack-hook"`), not Nix path literals or
`pkgs.writeText`, which would put the source secret in the store.
The generated `ossec.conf` holds a
token such as `@WAZUH_SECRET_integration-slack-hook_url@` in place of each
secret. `wazuh-server-setup.service` then puts each value where its reader
needs it:

- The GitHub token goes into `/var/ossec/etc/ossec.conf`, because
  `wazuh-modulesd` reads it from there. The file is mode 0640, owner root,
  group wazuh.
- Each integration secret goes into `/var/ossec/etc/secrets/<id>`, mode 0640,
  owner root, group wazuh. The token stays in `ossec.conf`.

`wazuh-integratord` gives the API key and the hook URL to the integration
program as command-line arguments. In this module, those arguments are the
tokens. The module replaces each program under `integrations/` with a
wrapper. The wrapper starts the packaged Python script through
`integration-secrets.py`, which reads the secret files and replaces the
tokens inside the Python process. So no secret is a process argument.

The upstream scripts write their arguments to `logs/integrations.log` on
every call, also without debug mode. An uncaught request error names the
URL path on stderr, and `wazuh-integratord` copies that output to
`ossec.log`. `integration-secrets.py` replaces each secret, and the path of a
secret URL, with `[secret]` in these outputs.

The Wazuh XML reader does not decode entities, so a secret is not escaped.
Each secret file must hold one line of printable ASCII. The line must not
contain a space, `<`, `$` or `\`. If a secret breaks this rule, the setup
unit stops with an error and leaves the installed `ossec.conf` unchanged.

The API can return the manager configuration. For API users without
permission to update the configuration, it masks only `authd.pass` and
`cluster.key` (`SENSITIVE_FIELD_PATHS` in
`framework/wazuh/rbac/decorators.py`). It does not mask the GitHub token. So
every API user who can read the manager configuration can read the GitHub
token. The integration secrets are not in `ossec.conf`, so the API does not
return them.

## Send alerts by e-mail and to a syslog server

`email.enable` runs `wazuh-maild`. `maild` speaks plain SMTP on port 25,
without authentication and without TLS. For a relay that needs either, run
a local relay or use `email.sendmail` with a program such as `msmtp`.
`emailAlerts` adds recipients for selected alerts. `reports` defines daily
reports that `wazuh-monitord` builds and mails after midnight.

`syslogOutput` runs `wazuh-csyslogd`, which sends selected alerts over UDP.

```nix
services.wazuh-server = {
  email = {
    enable = true;
    smtpServer = "127.0.0.1";
    from = "wazuh@example.com";
    to = [ "soc@example.com" ];
  };
  emailAlerts = [ { to = [ "oncall@example.com" ]; level = 10; doNotDelay = true; } ];
  syslogOutput = [ { server = "192.168.1.3"; level = 7; format = "json"; } ];
};
```

The upstream reference defines `email_alert_level` as the minimum alert
level for an e-mail. The generated default is 12. To mail lower levels, set
`settings.alerts.email_alert_level`. The VM check sets it to 5.

`database_output` is not available. Wazuh removed it upstream: version
4.14.8 has no `wazuh-dbd` and ignores the block with a deprecation warning.
The module refuses the block, so that a host does not expect alerts in a
database.

## Monitor devices without an agent

`agentless.checks` runs `wazuh-agentlessd`. It logs in to each device over
SSH through the upstream expect scripts under `agentless/`. The passwords
and the key come from root-only files. The setup unit writes the passwords
to `agentless/.passlist` and the key to `/var/ossec/.ssh`. The scripts send
a password over the terminal of the SSH session, not as a process argument.

```nix
services.wazuh-server.agentless = {
  checks = [
    { type = "ssh_integrity_check_linux"; hosts = [ "monitor@192.168.1.108" ];
      frequency = 3600; state = "periodic"; arguments = "/etc /usr/bin"; }
  ];
  credentials."monitor@192.168.1.108".passwordFile = "/run/secrets/agentless-monitor";
  knownHosts = "192.168.1.108 ssh-ed25519 AAAAC3...";
};
```

The upstream scripts answer "yes" to an unknown host key. The module sets
`StrictHostKeyChecking yes` instead, so `agentless.knownHosts` must list
every device. A password must be one line without `|`, because `|`
separates the fields of `.passlist`.

The `ssh_generic_diff` script sends its commands without waiting for the
prompt. So the captured output can vary from run to run, and a
`periodic_diff` check can alert without a change on the device.

## Run a manager cluster

`cluster` runs `wazuh-clusterd`. Every node needs the same `name` and the
same key in `keyFile`. The key must be 32 letters and digits. If it is
not, the setup unit stops and keeps the installed `ossec.conf`. The key is
written into the installed `ossec.conf`, where `wazuh-clusterd` reads it.
The API masks it.

```nix
services.wazuh-server.cluster = {
  nodeName = "master-node";
  nodeType = "master";
  keyFile = "/run/secrets/wazuh-cluster-key";
  nodes = [ "192.168.1.10" ];
};
```

`cluster.haproxyHelper` configures the HAProxy helper of the master. Its
passwords are written into the installed `ossec.conf`, and the API does not
mask them. The cluster reader splits a helper value at commas, so a helper
password must not contain a comma. The CA, client certificate and key are
installed under `etc/credentials` through `credentialFiles`. The option
bounds follow the schema that `wazuh-clusterd` checks, so a value that the
daemon would refuse fails at evaluation. The VM check parses a disabled
helper. It does not run the helper against a Data Plane API.

With `openFirewall`, the master opens `cluster.port`. The disabled
`settings.cluster` block of earlier configurations still works, but it
cannot be combined with `cluster`.

## Enroll an agent against the server

```sh
nix build .#checks.x86_64-linux.server-enrollment
```

The check boots two VMs. One runs `services.wazuh-server` with `auth.tls` from
the test PKI and `logAll = true`. The other runs `services.wazuh-agent` with
`manager.host = "server"`, the same enrollment password file, and
`registration.caFile` set to the test CA. It confirms five things:

1. The agent verifies the server certificate and enrolls against `authd`.
2. The server records the agent, under `registration.agentName`, in its own
   `/var/ossec/etc/client.keys`.
3. `wazuh-agentd` logs `(4102): Connected to the server` and reports
   `status='connected'`.
4. A journal entry written on the agent appears in the server's
   `logs/archives/archives.json`.
5. A journal entry that matches an `sshd` rule appears in
   `logs/alerts/alerts.json`.

The check also confirms that no `wazuh-*` unit failed on either VM and that
the server `ossec.log` holds no `CRITICAL` line. It needs no container image.

## Ship alerts to an indexer

Set `services.wazuh-server.indexer` to connect the server to a Wazuh
indexer. Every path points outside the Nix store. The user name and the
password are files with one line each, and PID 1 reads them, so they can be
root-only.

```nix
services.wazuh-server.indexer = {
  hosts = [ "https://indexer.example.net:9200" ];
  tls = {
    ca = "/run/secrets/wazuh-ca.pem";
    certificate = "/run/secrets/wazuh-server.pem";
    key = "/run/secrets/wazuh-server.key";
  };
  usernameFile = "/run/secrets/wazuh-indexer-username";
  passwordFile = "/run/secrets/wazuh-indexer-password";
};
```

The option drives three things. The generated `ossec.conf` enables the
`<indexer>` block and vulnerability detection. The setup unit writes the
user name and the password to the Wazuh keystore (`queue/keystore`) with
`wazuh-keystore`, which is where `wazuh-modulesd` reads them. The unit
`wazuh-filebeat` reads `logs/alerts/alerts.json` and writes each alert to
`wazuh-alerts-4.x-*` on the indexer.

`wazuh-filebeat` runs filebeat OSS 7.10.2 (`packages.filebeat-oss`), the
shipper the upstream server package installs, with the Wazuh filebeat module
and the index template from the pinned Wazuh source. The licensed filebeat
in nixpkgs (7.17) calls `GET /_license` on connect, and the indexer rejects
that call. filebeat loads the template and the ingest pipeline on every
connection to the indexer. The unit runs as the user `wazuh-filebeat`, a
member of the `wazuh` group, under the same sandbox as the daemons. It
writes only its registry under `/var/lib/wazuh-filebeat`. The credentials
and the TLS files reach it through `LoadCredential` and never enter the
store. `services.wazuh-server.filebeat` has these options:

| Option | Default | Meaning |
| --- | --- | --- |
| `enable` | `true` | Run `wazuh-filebeat` when `indexer` is set. |
| `package` | `packages.filebeat-oss` | The filebeat package. |
| `archives` | `false` | Also ship `logs/archives/archives.json`. Needs `logAll`. |
| `settings` | `{ }` | Extra `filebeat.yml` keys, merged over the generated ones. |

```sh
nix build .#checks.x86_64-linux.server-indexer
```

The check boots two VMs, the indexer and the server. It waits for the
indexer health, confirms the keystore and the enabled `<indexer>` block,
waits for filebeat to connect, writes an sshd line into a monitored file on
the server, and finds the resulting alert (rule 5710) in `wazuh-alerts-4.x-*`
with `curl` against the indexer.


## Manage rules, decoders and CDB lists

The manager reads its ruleset from three places.

| Directory in `/var/ossec` | Owner | Source |
|---|---|---|
| `ruleset/` | the package | The stock ruleset. The setup unit copies it at each activation. |
| `etc/declared/` | the configuration | The files of `ruleset.rules`, `ruleset.decoders` and `ruleset.lists`. |
| `etc/rules`, `etc/decoders`, `etc/lists` | the host | Files that the API or the dashboard editor writes. The module copies them one time from the package and then does not change them. |

Declare a file by its name:

```nix
services.wazuh-server.ruleset = {
  decoders."local_decoder.xml".source = ./local_decoder.xml;
  rules."local_rules.xml".text = ''
    <group name="local,">
      <rule id="100100" level="7">
        <decoded_as>my-app</decoded_as>
        <description>Event of my-app.</description>
      </rule>
      <rule id="100101" level="10">
        <if_sid>100100</if_sid>
        <list field="user" lookup="match_key">etc/declared/lists/blocked-users</list>
        <description>Event of my-app from a blocked user.</description>
      </rule>
    </group>
  '';
  lists."blocked-users".text = ''
    mallory:blocked
  '';
};
```

The setup unit installs the files as `root:wazuh` with mode `0640`. The
generated `ossec.conf` loads `etc/declared/decoders` and `etc/declared/rules`
after the stock directories and the host directories, and it has one `<list>`
for each declared list. Each `.xml` file in a declared directory loads. The
name does not have to end in `_rules.xml`. Use rule identifiers from 100000 to
120000, the range that upstream keeps for custom rules.

A rebuild is the only way to change a declared file. The API has no write
access to `etc/declared`. A file that leaves the configuration leaves the host
at the next activation, and `wazuh-analysisd` restarts with the new ruleset.

`wazuh-analysisd` compiles each list to `<name>.cdb` in the same directory, so
`etc/declared/lists` is writable for `wazuh-analysisd`. The sticky bit of the
directory prevents a replacement of the root-owned list.

The build of the system loads the declared files with `wazuh-analysisd -t`,
together with the stock ruleset and the generated `ossec.conf`. If
`wazuh-analysisd` reports an error or a warning, the build fails and shows the
message, and the running manager keeps its ruleset. A rule that names a list
which does not load is such a warning: the manager ignores that rule.

The build-time check has three limits:

- It does not see the files in `etc/rules`, `etc/decoders` and `etc/lists` of
  the host. It uses the package defaults for them.
- It does not run when a `source` is a string that names a host file. A build
  cannot read that file.
- `ruleset.validate = false` stops it.

In these three cases, an error shows only when `wazuh-analysisd` starts. It
does not start, and its journal names the file. Correct the file and rebuild.

An identifier must be unique in the three places. If a declared file and an
uploaded file define the same rule identifier or decoder name,
`wazuh-analysisd` uses or refuses them as upstream does. The module does not
compare the directories.

In a cluster, the master sends `etc/rules`, `etc/decoders` and `etc/lists` to
the workers. It does not send `etc/declared`. Declare the same files on each
node.

`settings.ruleset` still sets the stock and host directories, `rule_exclude`
and `decoder_exclude`. The module adds the declared directories after them.

```sh
nix build .#checks.x86_64-linux.server-ruleset-check
nix build .#checks.x86_64-linux.server-ruleset
```

The check boots one VM and writes events to the analysisd queue. It confirms
that a declared decoder, two declared rule files and a declared list give
alerts, that the API lists a declared rule and cannot write `etc/declared`,
and that a rule file uploaded through the API works after a restart of
`wazuh-analysisd`. It then activates a second configuration and confirms that
a removed rule file leaves the host, that its rule stops, and that a changed
list applies.

`server-ruleset-check` needs no VM. It confirms that the build-time check
accepts a good ruleset and refuses five bad ones.

## Structured server configuration

`services.wazuh-server.settings` uses upstream XML element names. Attribute
sets create nested elements, lists repeat elements in order, booleans become
`yes`/`no`, and `null` omits an element. `_attributes` supplies attributes;
`_text` supplies the text of an attributed element. For example:

```nix
services.wazuh-server.settings = {
  global.agents_disconnection_time = "10m";
  global.white_list = [ "127.0.0.1" "^localhost.localdomain$" "127.0.0.53" ];
  syscheck.auto_ignore = {
    _attributes = { frequency = 10; timeframe = 3600; };
    _text = false;
  };
  localfile = [{ log_format = "journald"; location = "journald"; }];
};
users.users.wazuh.extraGroups = [ "systemd-journal" ];
```

Settings merge recursively over generated defaults, so the example replaces
the disconnection timeout. Lists replace the entire default list: include
`/var/ossec/logs/active-responses.log` yourself when replacing `localfile`.
`settings` takes precedence over `logAll` and `alertLevel` in the XML; prefer
those dedicated options unless independent archive formats are needed.
`extraConfig` remains raw XML appended after the structured configuration.

Supported sections are `global`, `alerts`, `logging`, `rootcheck`, `syscheck`,
`sca`, `wodle`, `localfile`, `ruleset`, `rule_test`, `command`,
`active-response`, `vulnerability-detection`, and a disabled `cluster`.
Remote listeners, enrollment, indexer connections, integrations and GitHub
use their dedicated options because those also configure services and
credentials. `settings` cannot turn on e-mail or the cluster. Use
`email.enable` and `cluster` for those. Vulnerability detection requires an
indexer.

Wazuh's XML reader does not decode entities. The renderer therefore preserves
literal ampersands instead of changing their meaning to `&amp;`, rejects `<`
and trailing backslashes in text, and rejects quotes/angle brackets/newlines
in attributes. This follows Wazuh's reader, so output containing ampersands
may not parse with a standard XML library. It validates representation, not
all upstream section names, values, or operating-system permissions.

[examples/server-parity.nix](../../examples/server-parity.nix) translates a manager
configuration with two listeners, enrollment, FIM, rootcheck, SCA,
syscollector, indexer, VirusTotal, Slack and GitHub. It adapts Debian file
logs to journald and filesystem paths to NixOS. Command collectors run with
`services.wazuh-server.path`; they retain the service's permissions (for
example, unprivileged netstat cannot identify every process). The packaged
`restart-wazuh` command is intentionally absent because systemd owns restarts.
CIS-CAT and osquery stay disabled. Stock SCA policies target distributions
other than NixOS, and enabling inventory does not by itself supply the
agent module's Nix package inventory service. Configure suitable policies
and inventory sources for the host rather than assuming Debian results.

All `settings` and `extraConfig` values are public in the Nix store. Put API
keys, tokens and webhooks in the dedicated secret-file options; provision
the example's `/run/keys` files with your secret manager. TLS paths are
inputs: setup copies them into Wazuh's runtime directory.

`nix build .#checks.x86_64-linux.server-config` checks the merged configuration
with the native Wazuh readers, waits for each monitoring scan to finish,
and proves journald and command events reach the manager archive.

Structured `active-response` blocks require `activeResponse.enable = true`.
The generator places command definitions before response rules, as Wazuh
resolves command names while it reads the configuration. Enabling a rule
still requires the permissions described under `activeResponse.enable`;
the renderer does not grant firewall or account-management privileges.

## Manager reference extensions

The module targets the packaged Wazuh 4.14.8 readers. Native sections can use
`settings` with upstream element names, including `labels`, `agent-upgrade`,
`fluent-forward`, `ms-graph`, `office365`, `socket`, `task-manager`, `wdb`,
`gcp-pubsub` and `gcp-bucket`. The documentation heading “wazuh-db” corresponds
to the XML element `wdb`. Wodle names remain attributes, for example
`settings.wodle = [{ _attributes.name = "aws-s3"; disabled = true; }];`.

| Option | Default | Purpose |
|---|---|---|
| `secretFiles` | `{ }` | Named runtime source files for element-text secrets. Refer with `{ _secret = "name"; }` in `settings` or `auth.settings`. |
| `credentialFiles` | `{ }` | Named opaque files copied at activation to `/var/ossec/etc/credentials/<name>`, root:wazuh 0640. Refer with `{ _credential = "name"; }`. |
| `auth.settings` | `{ }` | Additional upstream auth fields, including force policy, ciphers, verification and timing. Cannot replace service-owned port, enable or credential paths. |
| `indexer.enable` | `true` | Enable the inventory indexer connector; independent of Filebeat alert shipping. |
| `indexer.tls.additionalCas` | `[ ]` | Additional CA files installed for the connector and Filebeat. |
| `remote.listeners.*.ridsClosingTime` | `null` | Secure listener RID file closing interval. |
| `remote.listeners.*.connectionOvertakeTime` | `null` | Connection takeover delay in seconds, 0–3600. |
| `remote.listeners.*.allowHigherVersions` | `null` | Whether a secure listener accepts newer agents. |
| `integrationScripts` | `{ }` | Python script paths keyed by `custom-*` integration name. Scripts use the packaged Python interpreter and the existing secret-redaction bootstrap. |

For example:

```nix
services.wazuh-server = {
  secretFiles.office = "/run/keys/office-client-secret";
  credentialFiles.google = "/run/keys/google-service-account.json";
  settings.office365.api_auth = {
    tenant_id = "tenant-id";
    client_id = "client-id";
    client_secret = { _secret = "office"; };
  };
  settings.gcp-pubsub.credentials_file = { _credential = "google"; };
};
```

Supply the remaining required upstream fields for each collector. Secret source
paths must be runtime strings outside the Nix store. Inline secret references
are refused in XML attributes and in `wodle`, `localfile`, `command`, `gcp-pubsub`, and `gcp-bucket`, where
upstream may expose text in subprocess arguments. Use collector credential files
or profiles there. Opaque credential files preserve whitespace and JSON bytes;
inline secrets follow the manager's existing single-line validation. Resolved
inline secrets are present in the installed configuration and visible to API
users allowed to read it. Upstream masks only `authd.pass` and `cluster.key`;
Office365, MS Graph and similar client secrets are readable by any API principal
allowed to read manager configuration. They are absent from the generated store
configuration.

When AWS, Azure, Google Cloud or Docker collectors are configured, the module
installs real, root-owned collector code below `/var/ossec/wodles`. AWS, Azure
and Google Cloud databases use `/var/ossec/var/wodles`, keeping writable state
separate from code. External API availability, account permissions and collector
configuration remain host responsibilities. Docker monitoring also requires
access to the host's Docker socket; the module does not grant that access
implicitly. Custom integrations currently support Python scripts only.
