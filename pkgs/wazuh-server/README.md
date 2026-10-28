# Wazuh server package

This is the native manager and API (`TARGET=server`). Alert shipping is owned
by the NixOS server module; indexer and dashboard have separate packages.

The package and `checks.server-package` are exported from `flake.nix`.
Dependency hashes are committed in `dependency-hashes.json`. To refresh them,
run `./pkgs/wazuh-server/prefetch-dependencies.sh` on a host that can reach
packages.wazuh.com, review the manifest, and commit it. The script fetches both
supported architectures and never changes the agent manifest. A complete server
package build and the package check have not yet passed; exported attributes
and verified downloads alone do not prove runtime behavior.

The package reuses agent build preparation and shared inputs. It adds upstream's
four manager dependencies and rebuilds CPython from the bundled archive after
discarding its shipped build state. The archive is not a plain source tree:
it can contain a prebuilt interpreter and a Makefile configured for Wazuh's
builder. The server preparation runs `distclean` when that Makefile exists,
removes the interpreter and generated configuration, and asserts their absence.
This forces upstream's `build_python` target to configure in the Nix sandbox
with the package output prefix before compiling Python. The exact framework
requirements are installed from the archive's local PEP 503 index. No nixpkgs Python
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

GCC 15 no longer includes `<cstdint>` through other libstdc++ headers. The vendored
rocksdb and 84 first-party headers use `uintN_t` without including it, so the
compiler reports missing declarations and then "has no member named" for every
use. The derivation passes `CXX=g++ -include cstdint` on the make command line.
That overrides the Makefile's own `CXX=g++`, reaches every recipe environment, and
CMake splits the argument into `CMAKE_CXX_COMPILER_ARG1`, which survives
sub-projects that replace `CMAKE_CXX_FLAGS`. It applies to g++ only; clang
compiles the BPF object as C and must not receive it. Patch 09 separately turns
off `FAIL_ON_WARNINGS` for rocksdb, which builds with `-Werror`. Retire both when
the sources include `<cstdint>` themselves. The agent never builds rocksdb and
its build is unchanged.
