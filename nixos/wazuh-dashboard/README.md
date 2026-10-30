# Run the Wazuh dashboard on NixOS

The dashboard provides the browser UI. It connects to an existing indexer for
search and to one or more existing Wazuh manager APIs for management data. This
module does not create those services or their accounts. Configure the indexer
first using the [indexer guide](../wazuh-indexer/README.md).

This guide describes `integration/server-stack` at `ff6dae8`, Wazuh 4.14.8.
The module and package are exported there, with verified release hashes. The
shared fast checks have reported passing results; dashboard package and VM
execution were still pending in the project thread when this guide was written.
The native manager module is not implemented at that revision; use an existing
reachable manager API, not an assumed `nixosModules.wazuh-server` export.

## Add the module to a host

### Prepare connections, certificates and credentials

Make the names `dashboard`, `indexer` and `manager` resolve on the relevant
machines, or substitute your real DNS names throughout the examples. Certificates
must contain the DNS SAN used by each client; a certificate subject alone is not
a hostname SAN. The browser must trust the dashboard certificate's issuing CA.

Provision the following files before service startup through your PKI and secret
manager (for example sops-nix or agenix), or as root-owned files in a private
`/var/lib/secrets/wazuh` directory:

| File under `/var/lib/secrets/wazuh/` | Contents/source |
|---|---|
| `dashboard.pem` | CA-issued server certificate covering DNS SAN `dashboard`; include needed intermediates. |
| `dashboard-key.pem` | Matching unencrypted private key. |
| `indexer-ca.pem` | PEM CA chain for the indexer certificate. |
| `indexer-username` | Single line `kibanaserver`, matching the indexer service account. |
| `indexer-password` | That account's plaintext password; corresponds to its indexer bcrypt hash. |
| `manager-ca.pem` | PEM CA chain for the manager API certificate. |
| `manager-username` | Existing manager API account, for example `wazuh-wui`. |
| `manager-password` | That account's plaintext API password. |

Create accounts and assign their permissions on their respective services first.
The module only consumes credentials. `kibanaserver` is the indexer's dashboard
service account, not a browser user's login. A browser user needs an indexer
security account with appropriate dashboard permissions. The example manager
account must have access to the manager information the UI requests; `runAs`
defaults false and does not grant any permissions.

Use one nonempty line per username/password file; a trailing newline is allowed.
Do not add quotes, a `username:` prefix, or YAML. Private files can be root-owned
mode `0600` in a mode `0700` directory: systemd reads them via `LoadCredential`.
The service user does not need access to the originals. Provisioning must finish
before `wazuh-dashboard.service` starts; configure secret-manager ordering when
necessary. Put quoted absolute path strings in Nix, not path literals or
`writeText` secrets, which put contents in the world-readable store.

### Import and configure

Add the integration branch as an input to your existing host `flake.nix`, then
commit the generated `flake.lock` to pin the resolved revision:

```nix
inputs.wazuh.url = "git+https://buzz.54rockybrook.house/git/ca2d2718d08212aa374355554aad2d2396c6531970fefebde668adce12889664/wazuh-agent.git?ref=integration/server-stack";
```

In the existing `nixosConfigurations.dashboard` module list, add the module and
configuration below. `inputs` is the argument of `outputs = inputs: ...`. Keep
your existing host/hardware configuration.

```nix
modules = [
  ./configuration.nix
  inputs.wazuh.nixosModules.wazuh-dashboard
  {
    networking.hostName = "dashboard";
    services.wazuh-dashboard = {
      enable = true;
      # Permit browser access from other machines. Omit both for local use.
      listenAddress = "0.0.0.0";
      openFirewall = true;
      tls = {
        certificate = "/var/lib/secrets/wazuh/dashboard.pem";
        key = "/var/lib/secrets/wazuh/dashboard-key.pem";
      };
      indexer = {
        hosts = [ "https://indexer:9200" ];
        ca = "/var/lib/secrets/wazuh/indexer-ca.pem";
        usernameFile = "/var/lib/secrets/wazuh/indexer-username";
        passwordFile = "/var/lib/secrets/wazuh/indexer-password";
      };
      managers = [
        {
          url = "https://manager";
          port = 55000;
          ca = "/var/lib/secrets/wazuh/manager-ca.pem";
          usernameFile = "/var/lib/secrets/wazuh/manager-username";
          passwordFile = "/var/lib/secrets/wazuh/manager-password";
        }
      ];
    };
  }
];
```

The manager URL is an origin **without a port, path or trailing slash**. Set its
port separately. Indexer URLs, in contrast, include the port. The example supplies
every required option; `package` is provided by the module, so no overlay is
needed. Rebuild from your host configuration checkout:

```bash
sudo nixos-rebuild switch --flake .#dashboard
```

Open `https://dashboard:5601` in a browser and sign in with an indexer user
permitted to use the UI. For co-location, import both modules on the same NixOS
host and retain DNS names that resolve locally and match the certificates. There
is no automatic endpoint discovery or dependency on a local indexer unit; the
configured remote services must already be available.

## Verify the service

```bash
systemctl status wazuh-dashboard.service
journalctl -u wazuh-dashboard -b --no-pager -n 100
curl --fail --show-error --cacert /path/to/dashboard-ca.pem \
  --user admin https://dashboard:5601/api/status
```

Use a public copy of the CA that issued `dashboard.pem` for the curl command.
`admin` here is an indexer user with suitable permissions, not the manager API
account or the dashboard service account. Curl prompts for its password. Expect
HTTP 200 and JSON with `status.overall.state` equal to `green`. The service should
be `active (running)`. A listening TCP port alone does not prove the indexer is
available.

Check that the running dashboard can use its configured manager credentials:

```bash
curl --fail --show-error --cacert /path/to/dashboard-ca.pem \
  --user admin -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"id":"manager-0"}' https://dashboard:5601/api/check-stored-api
```

The first entry in `managers` is `manager-0`, the next `manager-1`, and so on.
Expect `statusCode: 200` and `data.cluster_info` identifying the connected manager.
Do not count `data.apiIsDown: true` as success even if HTTP status is 200. Indexer
health and manager connectivity are separate checks.

Changing a credential file's contents does not automatically restart the service.
After rotating credentials or certificates at the same paths:

```bash
sudo systemctl restart wazuh-dashboard
```

Runtime configuration is under `/run/wazuh-dashboard`; persistent application
data is under `/var/lib/wazuh-dashboard`. Manager configuration is regenerated at
`/var/lib/wazuh-dashboard/wazuh/config/wazuh.yml` on each start, overwriting UI
changes to that file. Put lasting connection changes in Nix.

## Options

All names are relative to `services.wazuh-dashboard`. “Required” means no default
when enabled. Ports are integers from 1 to 65535. All file options are strings
naming existing runtime files.

| Option | Type | Default | Effect |
|---|---|---|---|
| `enable` | boolean | `false` | Start the dashboard service. |
| `package` | package | This flake's `pkgs/wazuh-dashboard` | Select dashboard distribution and plugins. |
| `listenAddress` | string | `"127.0.0.1"` | Browser-facing bind address. |
| `port` | port | `5601` | Browser-facing HTTPS port. Ports below 1024 add bind capability to the service. |
| `openFirewall` | boolean | `false` | Open `port` in the NixOS TCP firewall; does not change binding. |
| `tls.certificate` | string | Required | Dashboard HTTPS certificate file. |
| `tls.key` | string | Required | Matching unencrypted private key file. |
| `indexer.hosts` | list of strings | Required, nonempty | Indexer HTTPS URLs, including ports. |
| `indexer.ca` | string | Required | Indexer CA file; hostname and chain verification are enabled. |
| `indexer.usernameFile` | string | Required | Indexer service account name file, normally `kibanaserver`. |
| `indexer.passwordFile` | string | Required | Indexer service account plaintext password file. |
| `managers` | list of submodules | `[ ]`, rejected when enabled | Manager connections; IDs follow list order (`manager-0`, etc.). |
| `managers.*.url` | HTTPS-origin string | Required per entry | Manager origin without credentials, port, path, query or fragment; validated at startup as well as by Nix. |
| `managers.*.port` | port | `55000` | Manager API port, supplied separately from the origin. |
| `managers.*.usernameFile` | string | Required per entry | Manager API username file. |
| `managers.*.passwordFile` | string | Required per entry | Manager API plaintext password file. |
| `managers.*.runAs` | boolean | `false` | Request API run-as authentication; requires matching permissions on the manager. |
| `managers.*.ca` | null or string | `null` | Additional manager CA file; null retains Node's default trust, never disables verification. |
| `settings` | attribute set of JSON-serializable values | `{ }` | Extra OpenSearch Dashboards settings; module-managed endpoints, TLS, credentials and data path take precedence. Never put secrets here. |

Every manager CA is combined into one process-wide extra trust bundle. Trust is
not isolated per manager: a CA configured for one manager is trusted for the
others. The indexer connection uses its separately configured explicit CA file.

## Troubleshooting

Messages below are module diagnostics or common symptom fragments. They are not
a claim that all runtime paths have already passed deployment tests.

| Message or symptom | What to check and fix |
|---|---|
| `wazuh-dashboard.indexer.hosts must contain HTTPS URLs.` | Supply at least one `https://...:port` indexer URL. |
| `wazuh-dashboard.managers must contain at least one manager.` | Configure an existing manager API; an indexer alone is insufficient. |
| `...usernameFile ... is not of type string` | Pass a quoted filename string. A `writeText` derivation is not a string; only test fixtures should use such store-backed secrets, interpolated as `"${testFile}"`. |
| `Manager URL must be an HTTPS origin with port specified separately` | Use `url = "https://manager"; port = 55000;`, with no trailing slash or embedded credentials. |
| `Invalid single-line credential: ...` | Ensure the named file is nonempty and contains no embedded newline, carriage return or NUL. A trailing newline is stripped. |
| Missing credential file / `Failed to load credentials` | Provision the configured source path before the unit starts; check root access and secret-manager ordering. |
| `ECONNREFUSED` or browser connection refused | For the browser, check the dashboard bind/firewall; defaults accept loopback only. For downstream errors, check indexer/manager listeners, DNS and their firewalls. |
| Certificate issuer error / `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | Supply the correct CA chain for that connection; manager CA defaults do not automatically trust a private PKI. |
| `ERR_TLS_CERT_ALTNAME_INVALID` or hostname mismatch | Use a DNS name present in the server certificate SAN. An IP address requires an IP SAN. Do not switch off verification. |
| HTTP `401` or authentication error | Distinguish indexer service credentials, browser-user credentials and manager API credentials. Verify each against its own service; do not use bcrypt hashes as plaintext passwords. |
| HTTP `403` | Authentication succeeded but that account lacks permissions. Fix role assignments on the relevant service. |
| Status stays non-green / server not ready | Inspect the journal and check indexer health and the `kibanaserver` role mapping before debugging the UI. |
| Stored API check reports `apiIsDown` or an error | Verify `manager-0`, its port, CA, account and manager API permissions. The dashboard listening does not prove manager connectivity. |
| `Expected one compiled Wazuh API client` / `Unreviewed Wazuh TLS override` during package build | The release layout or TLS code differs from the packaging assumptions. Report the build log for a package fix; do not remove the verification gate. |

## Run the tests

From this repository on a Nix host with flakes enabled:

```bash
nix build -L .#checks.x86_64-linux.component-evaluation
nix build -L .#checks.x86_64-linux.component-rendering
nix build -L .#wazuh-dashboard
nix build -L .#checks.x86_64-linux.dashboard
```

The fast checks evaluate module combinations with stub packages and exercise
credential rendering and TLS patch boundaries. The VM test uses a real indexer,
a dashboard and a small TLS manager API fixture: **three VMs**, not a native
Wazuh manager. Allow at least the configured 3 GB indexer and 2 GB dashboard memory,
plus the fixture VM and host overhead, and a working NixOS VM-test/KVM environment.

The VM test checks HTTPS status, restart, credential access, the stored manager
connection through the running dashboard, and the packaged API client's behavior
with correct, wrong and absent additional CA trust. This does not establish
native manager integration or end-to-end agent event delivery. Those require the
separate stack work. Use the native system attribute for another supported
architecture and verify its package and VM support separately.

## Design and implementation notes

[default.nix](default.nix) defines the module; [configure.py](configure.py) writes
JSON-compatible YAML using systemd credentials. Generated files have restrictive
permissions. The service runs as `wazuh-dashboard` with writable runtime/state
directories and read-only system paths. Module-owned settings override values in
`settings`, including TLS enforcement and the persistent data path.

The module sets `opensearch.requestTimeout` to 120000 ms by default, and
`settings` can override it. The upstream default is 30 s. On a busy indexer,
the first creation of `.kibana_1` can take longer than that. After such a
timeout the index exists, and the dashboard waits forever for a migration
that no other instance runs.

Upstream Wazuh 4.14.8's API client explicitly sets `rejectUnauthorized: false`.
The package patches it to `true`, then conservatively scans executable server JS
in first-party Wazuh plugins for other verification/hostname overrides. An unknown
compiled layout fails the build. This is a source-pattern audit, not a general
proof about JavaScript; the VM tests exercise the compiled client too.

`NODE_EXTRA_CA_CERTS` loads the combined manager CA bundle when the process starts.
The indexer CA is configured explicitly in OpenSearch Dashboards. Restart after
CA rotation. When updating release artifacts, run
[prefetch.sh](../../pkgs/wazuh-indexer/prefetch.sh), rebuild the package and rerun
the tests; do not assume a successful hash update proves compatibility.
