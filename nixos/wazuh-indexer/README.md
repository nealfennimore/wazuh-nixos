# Run the Wazuh indexer on NixOS

The indexer stores and searches Wazuh events. This module runs the indexer and
initializes its security configuration. It does not start a manager, ship alerts,
or start a dashboard. Configure those separately; see the
[dashboard guide](../wazuh-dashboard/README.md).

This guide describes `integration/server-stack` at `ff6dae8`, Wazuh 4.14.8.
Release hashes and flake exports are present at that revision. The indexer package
and the two fast checks have build evidence reported in the project thread;
the indexer VM test and production deployment have not yet been verified there.

## Add the module to a host

### Prepare certificates and users

The module consumes existing files; it does not generate certificates, passwords,
or password hashes. Provision these before starting the service, using your PKI
and a secret manager such as sops-nix or agenix, or root-owned files under
`/var/lib/secrets/wazuh`. Keep private keys, passwords and hashes outside the Nix
store. Use quoted absolute path strings in Nix, not path literals or `writeText`
for production secrets. Systemd reads the source files as root through
`LoadCredential`; the daemon does not need direct access to their source directory.

For the configuration below, provision:

| File under `/var/lib/secrets/wazuh/` | Contents/source |
|---|---|
| `ca.pem` | PEM CA chain trusted for the indexer node and admin client. |
| `indexer.pem` | CA-issued node certificate, DNS SAN `indexer`, subject `CN=indexer,O=Example`; usable for server and client TLS. |
| `indexer-key.pem` | Matching unencrypted PKCS#8 private key. |
| `admin.pem` | Separate CA-issued admin client certificate, subject `CN=admin,O=Example`. |
| `admin-key.pem` | Matching unencrypted PKCS#8 private key. |
| `admin.hash` | Raw bcrypt hash of your chosen admin password. |
| `kibanaserver.hash` | Raw bcrypt hash of a separate dashboard service password. |

Use your actual certificate subjects in the configuration. Read the DN in the
order OpenSearch expects, and inspect the SAN:

```bash
openssl x509 -in indexer.pem -noout -subject -nameopt RFC2253
openssl x509 -in indexer.pem -noout -ext subjectAltName
openssl x509 -in admin.pem -noout -subject -nameopt RFC2253
```

Copy the subject value after `subject=` into the corresponding DN list. Do not
copy subjects from unrelated upstream examples. The admin certificate must be a
separate identity from the node certificate. If necessary, convert a key in a
private working directory with `umask 077`:

```bash
openssl pkcs8 -topk8 -nocrypt -in original.key -out indexer-key.pem
```

One way to generate each bcrypt hash interactively is:

```bash
nix shell nixpkgs#apacheHttpd -c htpasswd -nBC 12 admin | cut -d: -f2
nix shell nixpkgs#apacheHttpd -c htpasswd -nBC 12 kibanaserver | cut -d: -f2
```

Store each resulting hash as its own secret file, without a `username:` prefix.
The dashboard needs the **plaintext** kibanaserver password in its own credential
file, not this hash. Use distinct passwords. Production files can be root-owned
mode `0600`, with their parent directory mode `0700`. If using a secret manager,
ensure its provisioning unit finishes before these services start.

### Import and configure

Add this repository as an input to the host's existing `flake.nix`; commit
`flake.lock` to pin the resolved revision.

```nix
inputs.wazuh.url = "git+https://github.com/nealfennimore/wazuh-nixos";
```

In your existing `nixosConfigurations.indexer` module list, import the module and
add the configuration below. Here `inputs` is the argument of your flake's
`outputs = inputs: ...`; this is part of an existing NixOS host, not a replacement
for its hardware configuration.

```nix
modules = [
  ./configuration.nix
  inputs.wazuh.nixosModules.wazuh-indexer
  {
    networking.hostName = "indexer";
    services.wazuh-indexer = {
      enable = true;
      # Expose to the dashboard/manager on other hosts. Omit these two
      # settings for a deployment reachable only through local loopback.
      listenAddress = "0.0.0.0";
      openFirewall = true;
      nodeName = "indexer";
      nodeDistinguishedNames = [ "CN=indexer,O=Example" ];
      tls = {
        ca = "/var/lib/secrets/wazuh/ca.pem";
        certificate = "/var/lib/secrets/wazuh/indexer.pem";
        key = "/var/lib/secrets/wazuh/indexer-key.pem";
      };
      admin = {
        certificate = "/var/lib/secrets/wazuh/admin.pem";
        key = "/var/lib/secrets/wazuh/admin-key.pem";
        distinguishedNames = [ "CN=admin,O=Example" ];
        host = "indexer";
      };
      users = {
        admin = {
          passwordHashFile = "/var/lib/secrets/wazuh/admin.hash";
          backendRoles = [ "admin" ];
        };
        kibanaserver.passwordHashFile = "/var/lib/secrets/wazuh/kibanaserver.hash";
      };
    };
  }
];
```

Make `indexer` resolve to this host from client machines. Its certificate must
cover that name; using an IP URL requires a matching IP SAN. On the indexer itself,
NixOS normally maps its hostname to `127.0.0.2`, which the module keeps bound for
security administration even when you select a specific LAN address.

Apply from your host configuration checkout:

```bash
sudo nixos-rebuild switch --flake .#indexer
```

For a single machine with both modules, import both into that host and point the
dashboard at `https://indexer:9200`, with a matching local hostname/DNS mapping.
No overlay is required. Enable alert shipping separately on the manager; this
module does not enroll Wazuh agents.

## Verify the service

```bash
systemctl status wazuh-indexer.service wazuh-indexer-security.service
journalctl -u wazuh-indexer -u wazuh-indexer-security -b --no-pager -n 100
curl --fail --show-error --cacert /var/lib/secrets/wazuh/ca.pem \
  --user admin 'https://indexer:9200/_cluster/health?wait_for_status=yellow&timeout=30s'
```

Run the curl command as an account that can read the CA, or use a public copy of
the CA certificate. Curl prompts for the admin password; no password goes in the
command line. Expect HTTP 200 and JSON with `status` equal to `green` or `yellow`,
`timed_out` false, and the expected cluster name (`wazuh-cluster` by default).
A single node can be yellow because replicas cannot be allocated to a second
node. `red` is not healthy.

The daemon should be `active (running)`. The security unit is a oneshot and should
be `active (exited)` after applying users and roles. An active daemon alone does
not prove security initialization succeeded. Logs also live under
`/var/log/wazuh-indexer`; persistent index data lives under `/var/lib/wazuh-indexer`.

When rotating a secret at the same file path, restart the indexer to reload
systemd credentials and reapply security configuration:

```bash
sudo systemctl restart wazuh-indexer
```

Changes made directly through the security API can be overwritten on restart:
the security unit reapplies the package's security configuration and declared
users. Back up persistent index data before upgrades using an OpenSearch-supported
snapshot procedure; do not delete the data directory to fix authentication.

## Options

All names below are relative to `services.wazuh-indexer`. “Required” means no
default when enabled. Ports are integers from 1 to 65535.

| Option | Type | Default | Effect |
|---|---|---|---|
| `enable` | boolean | `false` | Enable daemon and security initialization. |
| `package` | package | This flake's `pkgs/wazuh-indexer` | Select indexer distribution and tools. |
| `listenAddress` | string or list of strings | `[ "127.0.0.1" "127.0.0.2" ]` | OpenSearch bind addresses; retains `127.0.0.2` unless `0.0.0.0` already covers it. |
| `port` | port | `9200` | HTTPS API port, also used by securityadmin. |
| `transportPort` | port | `9300` | Node-to-node transport port. |
| `openFirewall` | boolean | `false` | Open `port` in the NixOS TCP firewall; does not open transport or change binding. |
| `nodeName` | string | `networking.hostName` | Node identity and default admin connection hostname. |
| `clusterName` | string | `"wazuh-cluster"` | Cluster identity; passed to securityadmin too. |
| `singleNode` | boolean | `true` | Set `discovery.type = single-node`. |
| `heapSize` | string matching `[1-9][0-9]*[mgMG]` | `"1g"` | Both minimum and maximum JVM heap; leave memory for the OS and native allocations. |
| `nodeDistinguishedNames` | list of strings | Required, nonempty | Trusted node certificate subjects in RFC2253 order. |
| `tls.ca` | string | Required | Runtime PEM CA file. |
| `tls.certificate` | string | Required | Runtime node certificate file. |
| `tls.key` | string | Required | Runtime unencrypted PKCS#8 node key file. |
| `admin.certificate` | string | Required | Runtime admin client certificate file. |
| `admin.key` | string | Required | Runtime PKCS#8 admin key; not delivered to daemon. |
| `admin.distinguishedNames` | list of strings | Required, nonempty | Allowed security administrator certificate subjects. |
| `admin.host` | string | `nodeName` | Resolvable connection hostname matching the node SAN. |
| `users` | attribute set of user submodules | `{ }`, rejected when enabled | Complete declared internal user set; no demo users. |
| `users.<name>.passwordHashFile` | string | Required per user | Raw bcrypt hash file, not plaintext or an htpasswd record. |
| `users.<name>.backendRoles` | list of strings | `[ ]` | Backend roles mapped by upstream role mappings; `admin` grants full access. |
| `settings` | attribute set of JSON-serializable values | `{ }` | Extra OpenSearch settings; module-managed bind, TLS and state settings take precedence. |

The current module forces `vm.max_map_count = 262144`, sets `LimitNOFILE = 65536`,
and uses a separate system user for the daemon. These are implementation settings,
not additional module options. The `kibanaserver` username has an upstream mapping
to the dashboard service role; renaming it requires corresponding role mapping
support, which this module does not expose as a dedicated option.

For a cluster, set `singleNode = false`, provide discovery/bootstrap settings in
`settings`, supply every trusted node DN, and configure transport firewall access
between nodes explicitly. That also enables OpenSearch's production bootstrap
requirements. Multi-node deployment has no cluster VM test in this revision.

## Troubleshooting

These are diagnostic messages or symptom fragments, not claims of a completed
production deployment. Start with the two journals shown above.

| Message or symptom | What to check and fix |
|---|---|
| `wazuh-indexer.users must contain explicit users; demo passwords are never installed.` | Declare at least one user and its hash file. |
| `wazuh-indexer requires trusted node and admin certificate DNs.` | Set both nonempty DN lists from the actual certificates. |
| `Invalid bcrypt credential for indexer user` | Remove the htpasswd username prefix; supply a raw `$2a$`, `$2b$` or `$2y$` bcrypt hash. Do not supply plaintext. |
| Credential-loading error mentioning a missing file, or `Failed to load credentials` | Provision every configured path before service startup; check secret-manager ordering and root access. |
| `Connection refused` / security unit keeps restarting | Check `ss -ltn`, the port and `getent hosts indexer`. The default is loopback-only. For remote clients set a LAN bind and firewall access. For securityadmin, `admin.host` must resolve to a bound local address. |
| Certificate hostname/SAN mismatch | Use the DNS name in the SAN, or reissue the certificate with the required SAN. The subject DN alone does not establish hostname identity. |
| `PKIX path building failed` or curl certificate issuer error | Supply the correct CA chain and any required intermediates; verify node and admin certificates against it. Do not disable verification. |
| Admin certificate not recognized / securityadmin authorization failure | Check `admin.distinguishedNames` against `openssl ... -nameopt RFC2253`, and use the separate admin certificate/key pair. |
| HTTP `401` | Use a declared user's plaintext password corresponding to its stored bcrypt hash; wait for security initialization. There is no default admin password. |
| Security index not initialized | Inspect `wazuh-indexer-security` logs, including certificate, hash and connectivity errors. It retries failures; do not treat daemon readiness as success. |
| JVM allocation failure or OOM kill | Reduce `heapSize` or provide more RAM; the VM test uses a 512 MB heap on a 3 GB VM. |

## Run the tests

From this repository, on a Nix host with flakes enabled:

```bash
nix build -L .#checks.x86_64-linux.component-evaluation
nix build -L .#checks.x86_64-linux.component-rendering
nix build -L .#wazuh-indexer
nix build -L .#checks.x86_64-linux.indexer
```

The first two are shared fast checks: module evaluation with stub packages, and
credential/TLS-patch boundary tests. The VM test builds the actual package and
boots two indexer nodes; it needs a working NixOS VM-test/KVM environment and
memory for both 3 GB VMs plus host overhead. It tests health, auth, restart
persistence, credential permissions, and local versus remote binding. Change the
system attribute for a supported native architecture; artifact availability and
VM execution must be verified on that architecture.

## Design and implementation notes

[default.nix](default.nix) defines the options and units; [users.py](users.py)
renders runtime security users. Configuration and credentials are staged in
`/run/wazuh-indexer`; admin credentials belong only to the separate
`wazuh-indexer-security` DynamicUser service. The oneshot reapplies configuration
on daemon restart and retries on failure.

The package repacks Wazuh's release with its plugins and replaces the bundled JDK
with Nixpkgs headless Java 21. It is not a source build. When updating releases,
run [prefetch.sh](../../pkgs/wazuh-indexer/prefetch.sh) to refresh both indexer and
dashboard manifests, then rebuild and rerun the VM tests. A package build alone
does not prove service startup or event ingestion.
