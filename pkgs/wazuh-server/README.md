# Wazuh server package

This is the native manager and API (`TARGET=server`). Alert shipping is owned
by the NixOS server module; indexer and dashboard have separate packages.

This package is a draft until built. It is deliberately not exported from
flake.nix while verified server dependency hashes are missing. Run
`./pkgs/wazuh-server/prefetch-dependencies.sh` on a host that can reach
packages.wazuh.com, review `dependency-hashes.json`, and commit it. The script
fetches both supported architectures and never changes the agent manifest.
Then add these exports in the same commit:

```nix
packages.wazuh-server = pkgs.callPackage ./pkgs/wazuh-server { };
checks.server-package = import ./pkgs/wazuh-server/package-check.nix { inherit pkgs; };
```

The package reuses agent build preparation and shared inputs. It adds upstream's
four manager dependencies, builds the bundled CPython source and installs the
exact framework requirements from its local PEP 503 index. No nixpkgs Python
substitution or dependency relaxation is used. The install-only adjustments
remove ownership changes and certificate generation; activation owns runtime
identities and TLS material. Normal fixup and autoPatchelf repair bundled ELF
linkage. Network downloads during the native build are disabled with CURL=false.

Server-only patches give WAZUH_HOME precedence in the C++ helper and Python
framework. The module must set WAZUH_HOME=/var/ossec. Invoking a symlinked Python
alone does not guarantee that its installed modules retain the symlink prefix.
The package check imports wazuh, api and common through a symlinked runtime tree
and requires common.WAZUH_PATH to match the explicitly supplied mutable home.

`Privsep_Chroot` stays intact. A source guard runs after downstream patches and
requires all four upstream daemon call sites. The module/VM test must provide
CAP_SYS_CHROOT and a read-only store bind inside the runtime root, and exercise
the daemons. Source assertions cannot prove that the runtime mount works.

`package-check.nix` compiles a probe against the helper actually shipped by the
server build, checks invalid-home rejection and Python imports, and scans all
ELF interpreters and dynamic-link metadata for FHS or transient build paths.
It does not claim that every incidental /usr string in documentation, Python
stdlib tests, or debug data is a runtime dependency. VM execution remains the
integration proof.

Source checks without Nix (apply server patches to the pinned source first):

```sh
python3 pkgs/wazuh-server/test-source.py /path/to/patched/wazuh
```

This executes the actual Python path function with a store-shaped __file__,
checks each daemon's removed-chroot negative control, and runs the installer
preparation against real upstream files, including shell syntax checks. The
C++ executable probe requires a compiler and runs only in the package check.
