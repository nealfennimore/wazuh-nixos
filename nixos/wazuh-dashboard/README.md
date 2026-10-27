# Wazuh dashboard

Import this directory and enable `services.wazuh-dashboard`. It runs independently
of the other modules and defaults to HTTPS on loopback port 5601. Configure:

- `tls.{certificate,key}`: runtime HTTPS certificate and private key files.
- `indexer.{hosts,ca,usernameFile,passwordFile}`: HTTPS URLs with ports, CA file,
  and credentials for the dashboard service user (normally `kibanaserver`).
- `managers`: entries with `url` (HTTPS origin without port/path), `port` (55000),
  `usernameFile`, `passwordFile`, optional `ca` and `runAs` (false).

Systemd loads credentials; a Python renderer writes JSON-compatible YAML under
`/run/wazuh-dashboard` and `/var/lib/wazuh-dashboard/wazuh/config`. Credentials
must remain outside the Nix store. Declarative manager settings are restored on
restart, overwriting edits to wazuh.yml made through the UI. Mutable application
data remains under `/var/lib/wazuh-dashboard`.

The release package's Wazuh API client explicitly disables certificate checking.
The package patches that client to verify certificates, then audits executable
server JS across first-party Wazuh plugins, refusing other verification or
hostname overrides. Unknown binary layouts fail the build rather than silently
leaving insecure behavior. The audit is conservative text matching, not a proof
about arbitrary JavaScript. The actual compiled client is exercised in the VM
against the same endpoint with correct, incorrect and absent extra CA trust.

All configured manager CAs are concatenated into `NODE_EXTRA_CA_CERTS`. This is
process-wide additional trust, not per-manager isolation. A null CA retains
Node's default trusted roots; it never disables verification. The indexer
connection sets an explicit CA list separately. Hostnames must match DNS SANs.

The binary release and compiled plugin layout remain unverified until prefetch,
package build and VM checks run. See ../wazuh-indexer/README.md for prefetch and
fast-check wiring. Add these exports only with verified release hashes:

```nix
nixosModules.wazuh-dashboard = import ./nixos/wazuh-dashboard;
# Inside eachSystem:
packages.wazuh-dashboard = pkgs.callPackage ./pkgs/wazuh-dashboard { };
checks.dashboard = import ./nixos/tests/dashboard { inherit pkgs; };
```

The isolated dashboard VM uses a real indexer and a small TLS manager-API fixture.
It checks HTTPS readiness, restart, credential permissions, and the actual API
client's TLS behavior. The native manager connection and end-to-end event flow
belong to the separate stack check.
