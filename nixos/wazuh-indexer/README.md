# Wazuh indexer

Import this directory as a NixOS module. It is independent of the manager and
dashboard modules and defaults to HTTPS on loopback port 9200, with no firewall
opening. `openFirewall` opens HTTP only; cluster transport rules are explicit.

Required options under `services.wazuh-indexer`:

- `tls.{ca,certificate,key}`: runtime certificate paths; key is unencrypted PKCS#8.
- `nodeDistinguishedNames`: exact certificate subjects in RFC 2253 order.
- `admin.{certificate,key,distinguishedNames}`: securityadmin credentials and DNs.
  The daemon never receives the admin private key. `admin.host` defaults to
  `nodeName` and must resolve to this node and match its DNS SAN.
- `users.<name>.{passwordHashFile,backendRoles}`: bcrypt hash files and role lists.
  No upstream demo users are retained. `kibanaserver` is mapped by the upstream
  role mappings to the dashboard service role. Users with backend role `admin`
  have full access; use dedicated limited roles for production shippers.

The security unit reapplies declarative security configuration on restart.
Changes made directly through the security API can therefore be overwritten.
`singleNode` defaults true; multi-node deployments must disable it, supply
OpenSearch discovery settings, and explicitly open the transport port.

The package repacks the upstream release with its plugins, removes its bundled
JDK, and uses Nixpkgs headless Java 21. This is not a source build. Release hashes
are intentionally absent until `pkgs/wazuh-indexer/prefetch.sh` succeeds on a
network that can access packages.wazuh.com. The source layout and all runtime
behavior still require a build and VM run; source review is not build evidence.

Integration exports after hashes exist:

```nix
nixosModules.wazuh-indexer = import ./nixos/wazuh-indexer;
# Inside eachSystem:
packages.wazuh-indexer = pkgs.callPackage ./pkgs/wazuh-indexer { };
checks.indexer = import ./nixos/tests/indexer { inherit pkgs; };
```

Safe to wire before release hashes exist:

```nix
checks.component-evaluation = import ./nixos/tests/indexer/evaluation.nix { inherit pkgs; };
checks.component-rendering = import ./nixos/tests/dashboard/rendering.nix { inherit pkgs; };
```

The evaluation check explicitly passes a stub package to every enabled module;
it covers disabled, isolated and co-located modules plus invalid configuration.
The rendering check imports only Python source paths, never a release package.
Neither check proves the real services start. The indexer VM test covers TLS,
authentication, demo-password rejection, document persistence across restart,
key permissions and service identity.
