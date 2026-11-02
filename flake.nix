{
  description = "Wazuh agent package and NixOS module";

  # The binary cache that the build workflow fills. nix asks once before it
  # uses these; --accept-flake-config skips the question.
  nixConfig = {
    extra-substituters = [ "https://wazuh.cachix.org" ];
    extra-trusted-public-keys = [ "wazuh.cachix.org-1:NflEnqc62gXNPSzRtdOmuzDyfGK7yrTc6C2znraX3B8=" ];
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    let
      # The package is Linux only. Evaluating it for Darwin serves no purpose and
      # makes `nix flake check` report failures nobody can act on.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      wazuhModule =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nixos/wazuh-agent ];

          # Supply the package here so that the module works on its own. Without
          # this line the consumer must also apply overlays.default, or evaluation
          # fails with "attribute 'wazuh-agent' missing". mkDefault keeps
          # services.wazuh-agent.package overridable.
          services.wazuh-agent.package = lib.mkDefault (pkgs.callPackage ./pkgs/wazuh-agent.nix { });
        };
      # The server module, with its package supplied the same way.
      wazuhServerModule =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nixos/wazuh-server ];
          services.wazuh-server.package = lib.mkDefault (pkgs.callPackage ./pkgs/wazuh-server { });
        };
      # The throwaway test VM. examples/vm.nix imports qemu-vm.nix itself, so
      # this list evaluates both as a plain NixOS system and as a VM.
      vmModules = [
        wazuhModule
        ./examples/vm.nix
      ];
    in
    {
      overlays.default = final: _prev: {
        wazuh-agent = final.callPackage ./pkgs/wazuh-agent.nix { };
      };

      nixosModules.wazuh-agent = wazuhModule;
      nixosModules.default = wazuhModule;
      nixosModules.wazuh-server = wazuhServerModule;
      nixosModules.wazuh-indexer = import ./nixos/wazuh-indexer;
      nixosModules.wazuh-dashboard = import ./nixos/wazuh-dashboard;

      # For `nixos-rebuild build-vm --flake .#wazuh-agent-vm`.
      nixosConfigurations.wazuh-agent-vm = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = vmModules;
      };
    }
    // flake-utils.lib.eachSystem supportedSystems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        formatter = pkgs.nixfmt;
        packages.wazuh-agent = pkgs.callPackage ./pkgs/wazuh-agent.nix { };
        packages.default = pkgs.callPackage ./pkgs/wazuh-agent.nix { };

        # A bootable QEMU image with the agent enabled:
        #   nix build .#vm && ./result/bin/run-wazuh-agent-vm
        packages.vm =
          (nixpkgs.lib.nixosSystem {
            inherit system;
            modules = vmModules;
          }).config.system.build.vm;

        # A headless test of the module. It asserts activation and the
        # generated ossec.conf. It needs no manager, so it stays fast.
        checks.agent = import ./nixos/tests/agent/agent.nix {
          inherit pkgs wazuhModule;
        };

        # Fast component checks do not import release package derivations.
        checks.component-evaluation = import ./nixos/tests/indexer/evaluation.nix {
          inherit pkgs;
        };
        checks.component-rendering = import ./nixos/tests/dashboard/rendering.nix {
          inherit pkgs;
        };
        # Every module option appears in its README. Evaluation only, no VM.
        checks.options-documented = import ./nixos/tests/options-documented.nix {
          inherit pkgs nixpkgs;
          modules = {
            wazuh-agent = wazuhModule;
            wazuh-server = wazuhServerModule;
            wazuh-indexer = import ./nixos/wazuh-indexer;
            wazuh-dashboard = import ./nixos/wazuh-dashboard;
          };
          readmes = {
            wazuh-agent = ./README.md;
            wazuh-server = ./README.md;
            wazuh-indexer = ./nixos/wazuh-indexer/README.md;
            wazuh-dashboard = ./nixos/wazuh-dashboard/README.md;
          };
        };

        # Enrollment and delivery, against the Wazuh manager container image.
        # Kept separate from checks.agent on purpose: this one pulls a
        # multi-gigabyte image from Docker Hub and boots two VMs, and that
        # must not become a precondition for the fast test.
        #
        # The image pin is a checked-in JSON file that
        # nixos/tests/common/prefetch-manager-image.sh writes. Until it exists, this
        # check throws with instructions and checks.agent is unaffected,
        # because flake outputs evaluate lazily.
        checks.enrollment = import ./nixos/tests/agent/enrollment.nix {
          inherit pkgs wazuhModule;
        };

        # The upstream integration suites, run by pytest inside one VM. The
        # suite controls the daemons itself, so this check proves the built
        # binaries rather than the module. It is slow. The file documents the
        # shims it needs and takes the suite list and extra pytest flags as
        # arguments.
        checks.integration = import ./nixos/tests/agent/integration.nix {
          inherit pkgs wazuhModule;
        };

        packages.wazuh-server = pkgs.callPackage ./pkgs/wazuh-server { };
        checks.server-package = import ./pkgs/wazuh-server/package-check.nix { inherit pkgs; };
        # The server module in one VM: daemons up under the sandbox, the
        # four upstream chroots in place, ports open, ruleset loaded, API
        # answering with auth. It builds the server package first.
        checks.server = import ./nixos/tests/server { inherit pkgs wazuhServerModule; };
        checks.server-config = import ./nixos/tests/server-config { inherit pkgs wazuhServerModule; };
        checks.server-config-eval = import ./nixos/tests/server-config/eval.nix { inherit pkgs nixpkgs wazuhServerModule; };
        # The agent module against the server module, in two VMs: the agent
        # verifies authd with the test CA and enrolls, connects to remoted,
        # and an event written on the agent reaches the server's archive
        # and alert logs.
        checks.server-enrollment = import ./nixos/tests/server-enrollment {
          inherit pkgs wazuhModule wazuhServerModule;
        };
        # Alert shipping: the server and an indexer in two VMs, the
        # keystore written, filebeat connected, and an alert from the
        # manager found in wazuh-alerts-4.x-*. Needs about 6 GB for the
        # two VMs.
        checks.server-indexer = import ./nixos/tests/server-indexer { inherit pkgs wazuhServerModule; };
        # A second remoted listener (syslog on 514/udp), integratord and the
        # Slack integration against a local webhook, and the secret handling
        # for integrations and the GitHub module, in two VMs.
        checks.server-runtime = import ./nixos/tests/server-runtime { inherit pkgs wazuhServerModule; };
        # wazuh-maild against a local SMTP receiver and wazuh-csyslogd
        # against a local UDP receiver, in one VM.
        checks.server-optional = import ./nixos/tests/server-optional { inherit pkgs wazuhServerModule; };
        # filebeat OSS 7.10.2, the shipper the upstream server package
        # installs. nixpkgs filebeat7 is the licensed build and refuses the
        # indexer (GET /_license on connect).
        packages.filebeat-oss = pkgs.callPackage ./pkgs/filebeat-oss { };
        packages.wazuh-indexer = pkgs.callPackage ./pkgs/wazuh-indexer { };
        checks.indexer = import ./nixos/tests/indexer { inherit pkgs; };
        packages.wazuh-dashboard = pkgs.callPackage ./pkgs/wazuh-dashboard { };
        checks.dashboard = import ./nixos/tests/dashboard { inherit pkgs; };
        # The full stack in four VMs: the agent enrolls against the native
        # server, its alert reaches the indexer through filebeat, and the
        # dashboard answers against the indexer and the server API. Needs
        # about 9 GB for the four VMs.
        checks.stack = import ./nixos/tests/stack {
          inherit pkgs wazuhModule wazuhServerModule;
        };
        # The dashboard against services.wazuh-server instead of a fake API.
        checks.dashboard-server = import ./nixos/tests/dashboard/server.nix {
          inherit pkgs wazuhServerModule;
        };

        # The wazuh_testing package on its own, so a broken build or a stale
        # source hash surfaces in seconds instead of at VM start:
        #   nix build .#wazuh-testing
        packages.wazuh-testing = pkgs.callPackage ./pkgs/wazuh-testing.nix { };

        # `.envrc` runs `use flake`. Without this shell, direnv falls back to
        # the build environment of packages.default, which pulls the whole
        # dependency closure to open a prompt.
        devShells.default = pkgs.mkShellNoCC {
          packages = [
            pkgs.nixfmt
            pkgs.curl
            pkgs.gitMinimal
            # examples/show-cpe-map.sh pretty-prints with it.
            pkgs.jq
          ];
        };
      }
    );
}
