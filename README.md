# Wazuh on NixOS

A Nix flake that packages the Wazuh security platform and runs each of its
components as a NixOS module. The flake holds the agent, the manager and its
API, the indexer, the dashboard, and the filebeat build that ships alerts.

The flake targets Wazuh 4.14.8 with external dependency set `DEPS_VERSION=54`.
The packages evaluate for `x86_64-linux` and `aarch64-linux`. CI builds the
agent for both systems and the server stack for `x86_64-linux` only.

## Components

Each NixOS module has its own guide. The guide gives the setup steps, every
option of the module, the troubleshooting steps and the checks.

| Component | Module | Guide | Purpose |
|-----------|--------|-------|---------|
| Agent | `services.wazuh-agent` | [nixos/wazuh-agent/README.md](nixos/wazuh-agent/README.md) | Collects logs, file changes, the package inventory and scan results on a host. |
| Server | `services.wazuh-server` | [nixos/wazuh-server/README.md](nixos/wazuh-server/README.md) | The manager: enrolls agents, analyzes their events, writes alerts and runs the Wazuh API. Ships alerts to the indexer with filebeat. |
| Indexer | `services.wazuh-indexer` | [nixos/wazuh-indexer/README.md](nixos/wazuh-indexer/README.md) | Stores and searches alerts and inventory data. |
| Dashboard | `services.wazuh-dashboard` | [nixos/wazuh-dashboard/README.md](nixos/wazuh-dashboard/README.md) | The browser UI. Reads the indexer and the server API. |

The data flows in this order:

1. The agent enrolls with the server on port 1515.
2. The agent sends its events to the server on port 1514.
3. The server writes alerts, and `wazuh-filebeat` sends them to the indexer on port 9200.
4. The dashboard reads the indexer on port 9200 and the server API on port 55000.
5. Users open the dashboard on port 5601.

The agent module and the server module cannot share a host. Both own
`/var/ossec` and the `wazuh` account. The manager monitors its own host.

Other documents:

- [pkgs/wazuh-server/README.md](pkgs/wazuh-server/README.md): how the manager and API package is built.
- [pkgs/common/README.md](pkgs/common/README.md): the source and the inputs that the agent and server packages share.
- [pkgs/patches/README.md](pkgs/patches/README.md): the downstream patches and the reason for each.
- [docs/implementation-status.md](docs/implementation-status.md): the agent configuration sections that the agent module covers.
- [docs/manager-reference.md](docs/manager-reference.md): the manager reference sections and the server option that covers each one.
- [examples/](examples): a consumer flake, an agent host, and server configurations.

## Flake outputs

| Output | Purpose |
|--------|---------|
| `nixosModules.wazuh-agent` | The `services.wazuh-agent` module. `nixosModules.default` is the same module. |
| `nixosModules.wazuh-server` | The `services.wazuh-server` module. |
| `nixosModules.wazuh-indexer` | The `services.wazuh-indexer` module. |
| `nixosModules.wazuh-dashboard` | The `services.wazuh-dashboard` module. |
| `packages.wazuh-agent` | The agent build. `wazuh-control` is the main program. `packages.default` is the same package. |
| `packages.wazuh-server` | The server build: manager daemons, API and bundled CPython. |
| `packages.wazuh-indexer` | The indexer, from the upstream release package. |
| `packages.wazuh-dashboard` | The dashboard, from the upstream release package. |
| `packages.filebeat-oss` | filebeat OSS 7.10.2, the alert shipper that the upstream server package installs. |
| `packages.wazuh-testing` | The upstream integration test framework, for `checks.integration`. |
| `packages.vm` | A QEMU VM with the agent enabled. |
| `nixosConfigurations.wazuh-agent-vm` | The same VM, for `nixos-rebuild build-vm`. |
| `overlays.default` | Adds `wazuh-agent` to a package set. |
| `checks.*` | The checks in [Run the checks](#run-the-checks). |
| `devShells.default` | A shell for work on this repository. |
| `formatter` | `nixfmt`. |

Each module supplies its own package. The overlay is optional.

## Add the flake to a host

1. Add the flake as an input.

   ```nix
   inputs.wazuh.url = "git+https://github.com/nealfennimore/wazuh-nixos";
   ```

2. Import the module for the role of the host.

   ```nix
   {
     imports = [ inputs.wazuh.nixosModules.wazuh-server ];
   }
   ```

3. Set the options from the guide of that module.
4. Rebuild the host.

   ```bash
   sudo nixos-rebuild switch
   ```

The input name `wazuh-agent` is the name that the guides and `examples/` use.
Any input name works.

## Deploy the full stack

Each component connects to a component above it in this list. Deploy them in
this order:

1. The indexer. Prepare its certificates and user hashes, then start it. See
   the [indexer guide](nixos/wazuh-indexer/README.md).
2. The server. Set `services.wazuh-server.indexer` to the indexer URL, the CA
   and a client certificate. See
   [Ship alerts to an indexer](nixos/wazuh-server/README.md#ship-alerts-to-an-indexer).
3. The dashboard. Point `indexer` at the indexer and `managers` at the server
   API. See the [dashboard guide](nixos/wazuh-dashboard/README.md).
4. The agents. Point `manager.host` at the server. See the
   [agent guide](nixos/wazuh-agent/README.md).

The checks use one certificate authority for the whole stack. The indexer, the
server API, `authd` and the dashboard each present a certificate from it, and
each client verifies its peer with the same CA file. Keep every private key,
password and hash outside the Nix store. Each module reads them from runtime
paths through systemd `LoadCredential`.

`checks.stack` deploys the four components in this order on four VMs. Its
configuration in `nixos/tests/stack` is a working example of the wiring.

## Run the checks

Each check is a flake output. Build it with `nix build`:

```bash
nix build .#checks.x86_64-linux.<name>
```

| Check | VMs | What it proves |
|-------|-----|----------------|
| `options-documented` | none | Every option of the four modules appears in its guide. |
| `component-evaluation` | none | The indexer and dashboard modules evaluate in their supported combinations. |
| `component-rendering` | none | The dashboard credential rendering and the TLS patch boundaries. |
| `server-package` | none | The server binaries, the Python framework and API imports, and the ELF links. |
| `server-config-eval` | none | The server configuration renderer and its assertions. |
| `agent` | 4 | Agent activation, the generated `ossec.conf`, journal collection, the daemon PATH and the active-response grants. |
| `enrollment` | 2 | The agent enrolls with the Wazuh manager container image and delivers an event. |
| `integration` | 1 | The upstream agent integration suites run against the built binaries. Takes several hours. |
| `server` | 2 | The server daemons, chroots, ports, ruleset, API users, the API guard and API authentication. |
| `server-config` | 1 | The structured configuration against the native Wazuh readers, and the monitoring scans. |
| `server-reference` | 1 | The manager reference extensions: parsers, credential placement and custom integrations. |
| `server-enrollment` | 2 | The agent module enrolls with the server module and delivers events and alerts. |
| `server-indexer` | 2 | filebeat ships a server alert to the indexer. |
| `server-runtime` | 2 | A syslog listener, `wazuh-integratord`, the Slack integration and secret handling. |
| `server-optional` | 1 | `wazuh-maild` and `wazuh-csyslogd` against local receivers. |
| `server-ruleset` | 1 | Declared rules, decoders and CDB lists reach `wazuh-analysisd`, and a removed file leaves the host. |
| `server-ruleset-check` | none | The build-time check accepts a good declared ruleset and refuses bad ones. |
| `server-agentless` | 2 | `wazuh-agentlessd` against an SSH target. |
| `server-cluster` | 2 | `wazuh-clusterd` on a master and a worker. |
| `indexer` | 2 | The indexer, its security configuration, and the rotation and recovery of declared user hashes. |
| `dashboard` | 3 | The dashboard against an indexer and a test manager API. |
| `dashboard-server` | 3 | The dashboard against `services.wazuh-server`. |
| `stack` | 4 | The agent, server, indexer and dashboard together. |

The guide of each module describes its checks in more detail. CI runs every
check except `integration`. See [Use the binary cache](#use-the-binary-cache).

### Run the full stack check

```sh
nix build .#checks.x86_64-linux.stack
```

The check boots four VMs: `agent`, `server`, `indexer` and `dashboard`. It
needs about 9 GB of memory for the VMs. The indexer VM runs the fixture
from `nixos/tests/indexer/fixture.nix`. The server VM runs
`services.wazuh-server` with `auth.tls`, `api.tls`, `api.users` and
`indexer` set, all from the test PKI. The agent VM runs `services.wazuh-agent`
with the same configuration as the enrollment check. The dashboard VM runs
`services.wazuh-dashboard` with `indexer` pointed at the indexer VM and
`managers` pointed at `https://server:55000` as the user `wazuh-wui`.

The VMs start in order: the indexer, then the server, then the agent and the
dashboard together. The subtests run in this order:

1. The indexer answers with the security configuration applied.
2. The server daemons run, `remoted` and `authd` listen, and the keystore
   holds the indexer credentials.
3. The API listens, `wazuh-api-users.service` set the passwords, and the
   API authenticates with the test PKI.
4. The agent enrolls against `authd` and connects to `remoted`.
5. A journal entry written on the agent appears in the server's
   `archives.json`.
6. An alert from the agent appears in `wazuh-alerts-4.x-*` on the indexer.
7. The dashboard status API reports `green`.
8. No `wazuh-*` unit failed on any VM, and the server `ossec.log` holds no
   `CRITICAL` line.
9. The dashboard holds the server in `wazuh.yml`, trusts only the test CA
   for the manager connection, and `/api/check-stored-api` reaches the
   server API.

The last subtest is separate on purpose. The `managers` wiring against the
native API has no check of its own yet. A failure there leaves every earlier
result in the log. Every timeout is sized for a shared builder. The indexer
takes about 400 s to security-ready there, and the API took 350 s to listen.

## Build the packages

```bash
nix build .#wazuh-agent
nix build .#wazuh-server
nix build .#wazuh-indexer
nix build .#wazuh-dashboard
```

The agent and server builds fetch dependency tarballs from
`packages.wazuh.com`, and the indexer and dashboard come from release packages
on the same server. The build host must reach that server.

## Use the binary cache

GitHub Actions builds `wazuh-agent` for both systems, and the server stack
(`wazuh-server`, `wazuh-indexer`, `wazuh-dashboard`, `filebeat-oss`) for
`x86_64-linux`, on every push to `main` and to `integration/server-stack`,
and pushes the results to Cachix. The workflow is
`.github/workflows/build.yml`. Pushes, pull requests and manual dispatches
all run the five non-VM checks and the 15 VM checks listed in
`.github/vm-checks/*.txt` on `x86_64-linux`. This includes every manager-reference
check, container enrollment, native server enrollment, indexing, dashboard,
and the full stack. Five groups run on separate runners (at most three groups
at once); Docker-image enrollment has its own group. Within a group, VM checks
run sequentially, continue after individual
failures, and fail the job if any check fails. Logs, derivation paths and a
result summary are uploaded as `vm-check-logs-<group>`, including on failure.

The build jobs export compressed Nix package closures as one-day artifacts.
The test job imports those exact packages, so fork PRs need no cache-write
credentials and do not rebuild the manager once per test. The runner frees
unused toolchains and adds 12 GiB of swap for multi-VM tests; the largest
test configures about 9 GiB of guest RAM. Low-memory runners may run slowly.
Each VM group has a six-hour limit. The only excluded flake check is
`checks.integration`: its upstream agent suite has a 12-hour test limit and
must run separately on a sufficiently provisioned KVM builder. Live external
service validation still requires staging credentials and endpoints.

To use the cache, add it to the host that builds the agent:

```nix
nix.settings = {
  substituters = [ "https://wazuh.cachix.org" ];
  trusted-public-keys = [ "wazuh.cachix.org-1:NflEnqc62gXNPSzRtdOmuzDyfGK7yrTc6C2znraX3B8=" ];
};
```

The flake also declares the cache in `nixConfig`. A `nix build` of this flake
offers to add the substituter and the key once, and `--accept-flake-config`
accepts them without the prompt. The key is on the cache page at
`https://app.cachix.org`.

The cache holds the build that fetches the Wazuh source from GitHub. A flake
input without `?submodules=1`, as in the first section, produces the same
store path and gets a cache hit. A local checkout with the `modules/wazuh`
submodule populated produces a different store path and builds from source.

### Set up the workflow

1. Create a cache at `https://app.cachix.org`.
2. Create an auth token for the cache with write access.
3. Add the token as the repository secret `CACHIX_AUTH_TOKEN`.
4. If the cache is not named `wazuh`, add the repository
   variable `CACHIX_CACHE` with its name.

Pull requests build but do not push. The `aarch64-linux` job uses the
`ubuntu-24.04-arm` runner, which GitHub provides at no cost to public
repositories only.

## Move to a new Wazuh version

`scripts/upgrade-wazuh.sh` moves every Wazuh pin in the repository to one
version. The agent and the server share one source pin in
`pkgs/common/default.nix`. The indexer and the dashboard have their own
release pins.

Run the script on a host that can reach GitHub, `packages.wazuh.com` and
Docker Hub.

1. In VS Code, run the task **Wazuh: upgrade to a new version**.
   Alternatively, run the script in a terminal:

   ```bash
   nix develop --command ./scripts/upgrade-wazuh.sh 4.14.10
   ```

2. Enter a version without the `v`, or `latest` for the newest release.
3. Read the changes with `git diff` and `git diff --cached modules/wazuh`.
4. Run the checks, then commit.

The script does these steps:

1. It reads the commit of the tag `v<version>` on `wazuh/wazuh`.
2. It reads `DEPS_VERSION`, `HTTP_REQUEST_BRANCH` and the `EXTERNAL_RES`
   dependency lists from `src/Makefile` at that tag. The agent list is the
   `EXTERNAL_RES :=` line. The server adds the names on the `EXTERNAL_RES +=` line.
   A new upstream dependency thus gets a hash without an edit.
3. It writes `version`, `dependencyVersion`, `wazuhRev` and the hashes of the
   GitHub sources into `pkgs/common/default.nix`.
4. It moves `pkgs/wazuh-testing.nix` to the same `qa-integration-framework` tag.
   If that tag does not exist, the file does not change.
5. It runs `pkgs/dependencies/prefetch-external-dependencies.sh` and
   `pkgs/wazuh-server/prefetch-dependencies.sh` with the lists from step 2.
6. It sets `version` and `revision` in `pkgs/wazuh-indexer/source.json` and
   `pkgs/wazuh-dashboard/source.json`, then runs `pkgs/wazuh-indexer/prefetch.sh`.
7. It pins the manager container image for `checks.enrollment`. See
   [Run the enrollment test](nixos/wazuh-agent/README.md#run-the-enrollment-test).
   The image is several GB. Use `--skip-manager-image` to skip this step.
8. It moves the `modules/wazuh` submodule commit.

The script does not commit. If a step fails, the script restores every pin
file and exits 1. If the pins already name the version, the script changes
nothing. The last line of its output is `changed <old> <new>` or
`current <version>`. Run `./scripts/upgrade-wazuh.sh --help` for all options.

The script does not move the `libbpf-bootstrap` rev in `pkgs/common/default.nix`.
If the build of a new version fails in the eBPF step, read that rev in the
upstream source.
