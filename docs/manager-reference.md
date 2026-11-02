# Manager configuration coverage

This maps Neal's `wazuh-manager-ossec-conf-reference.md` (Wazuh 4.14
reference) to the NixOS module and its packaged Wazuh **4.14.8**. XML
representation is checked by the module; upstream readers validate individual
field names, combinations and values. A documented section is not a promise
that a remote API or an external executable is configured on a host.

| Reference section | NixOS configuration |
|---|---|
| active-response | `settings.active-response`, with `activeResponse.enable` |
| agent-upgrade | `settings.agent-upgrade` |
| agentless | Dedicated optional-service module |
| alerts | `settings.alerts`, or `alertLevel` |
| auth | `auth.*`, additional native fields in `auth.settings` |
| cluster | Dedicated optional-service module; disabled raw `settings.cluster` remains compatible |
| command | `settings.command` (rendered before active-response) |
| database_output | Removed by upstream; rejected rather than silently ignored |
| email_alerts | `emailAlerts`, with `email.enable` |
| fluent-forward | `settings.fluent-forward` |
| gcp-bucket | `settings.gcp-bucket` |
| gcp-pubsub | `settings.gcp-pubsub` |
| github | `github.*` |
| global | `settings.global`; email fields through `email.*` |
| indexer | `indexer.*` |
| integration | `integrations.<name>`; custom Python through `integrationScripts` |
| labels | `settings.labels` |
| localfile | `settings.localfile` |
| logging | `settings.logging` |
| ms-graph | `settings.ms-graph` |
| office365 | `settings.office365` |
| remote | `remote.listeners` |
| reports | `reports`, with email configured |
| rootcheck | `settings.rootcheck` |
| rule_test | `settings.rule_test` |
| ruleset | `settings.ruleset` |
| sca | `settings.sca` |
| socket | `settings.socket` |
| syscheck | `settings.syscheck` |
| syslog_output | `syslogOutput` |
| task-manager | `settings.task-manager` |
| vulnerability-detection | `settings.vulnerability-detection`, with enabled `indexer` |
| wazuh-db | `settings.wdb` (the actual upstream XML name) |
| wodle agent-key-polling | `settings.wodle` with `_attributes.name = "agent-key-polling"` |
| wodle aws-s3 | `settings.wodle` with `_attributes.name = "aws-s3"` |
| wodle azure-logs | `settings.wodle` with `_attributes.name = "azure-logs"` |
| wodle command | `settings.wodle` with `_attributes.name = "command"` |
| wodle docker-listener | `settings.wodle` with `_attributes.name = "docker-listener"` |
| wodle osquery | `settings.wodle` with `_attributes.name = "osquery"` |
| wodle syscollector | `settings.wodle` with `_attributes.name = "syscollector"` |

## Runtime requirements

Use `path` for external collector commands. Configure osquery and its actual
log paths on the host. Docker monitoring needs access to the Docker socket.
Agent-key polling needs its configured executable or socket. Native settings
retain upstream names and defaults, including upstream platform restrictions.

`secretFiles` inserts referenced secrets only in the installed configuration;
`credentialFiles` installs opaque profile files, JSON keys and certificates.
Never put secret values directly in Nix expressions. API users with permission
to read manager configuration can read inserted secrets unless upstream masks
that specific field. Cloud authentication and successful external requests
require valid accounts and network access and are not exercised by offline VMs.

Collector code stays root-owned. AWS, Azure and Google Cloud databases are
relocated into `var/wodles` because upstream otherwise writes beside its code.
The reference VM creates those databases as the daemon user using the actual
packaged Python modules; external cloud client creation is mocked.

`server-reference` checks native parsers, credential placement, cloud database
paths and custom Python integration delivery. Existing `server-config` checks
rootcheck, syscheck, SCA, syscollector, journald and command collection.
`server-runtime` checks listeners, Slack delivery to a local receiver, and
integration secret protection. Optional service checks cover their respective
local protocol peers. See the implementation report for which checks passed at
the final commit; the table alone is not test evidence.
