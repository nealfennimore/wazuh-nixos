# Shared Wazuh inputs

`default.nix` pins the source, version and shared external inputs. Agent and
server packages use these exact inputs. The existing dependency manifest and
patch files remain at `pkgs/dependencies` and `pkgs/patches` to preserve their
public paths and store path names. `pkgs/wazuh-agent.nix` remains a compatibility
entry point; the agent derivation now lives in `pkgs/wazuh-agent/default.nix`.

Phase 0 must be checked with Nix before claiming derivation identity:

```sh
nix eval .#packages.x86_64-linux.wazuh-agent.drvPath
nix eval .#checks.x86_64-linux.agent.drvPath
```

Compare each result on baseline `2310b9b` and the restructure commit, with the
same submodule availability. The move intentionally changes no derivation
attribute values. Source inspection is insufficient to prove that.
