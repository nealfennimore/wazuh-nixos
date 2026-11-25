{ fetchFromGitHub, fetchurl, lib }:
let
  # Keep these three in step with the modules/wazuh submodule pin.
  # dependencyVersion mirrors DEPS_VERSION in src/Makefile at the same tag.
  version = "4.14.11";
  dependencyVersion = "56";
  wazuhRev = "8305693956b88042917970c8d22b1277d41865cf";

  external_dependencies = import ../dependencies {
    inherit fetchurl lib dependencyVersion;
  };

  # modules/wazuh is a git submodule. Nix only sees its contents when the flake
  # is evaluated with submodules enabled, for example:
  #   nix build 'git+file:///path/to/repo?submodules=1#wazuh-agent'
  # When it is empty, fall back to fetching the same commit, so a plain
  # `nix build .#wazuh-agent` still works.
  submodule = ../../modules/wazuh;
  haveSubmodule = builtins.pathExists (submodule + "/src/Makefile");
  wazuhSrc =
    if haveSubmodule then
      submodule
    else
      fetchFromGitHub {
        owner = "wazuh";
        repo = "wazuh";
        rev = wazuhRev;
        sha256 = "sha256-Kad5yE+8aLxH2LTMOIH3riBqYuF3xXHmKp8klSC1brw=";
      };

  # rev mirrors HTTP_REQUEST_BRANCH in src/Makefile at the same tag.
  wazuh-http-request = fetchFromGitHub {
    owner = "wazuh";
    repo = "wazuh-http-request";
    rev = "cd50797cfe03c27f3759bdc243fecca6f7535d35";
    sha256 = "sha256-K8wgvsoOeCJyn1z9P7E/g2w7x0Jt5BjUhakK1eyUYeA=";
  };

  libbpf_bootstrap_deps = {
    bootstrap = fetchFromGitHub {
      owner = "libbpf";
      repo = "libbpf-bootstrap";
      rev = "aa18cc0d8fc8ef4104fb74d218ae6a20cf6eb176";
      sha256 = "sha256-ggIDf/I4QlSypFpsRibsdWd9bSevC2mfyEenlYZQdqI=";
      fetchSubmodules = true;
    };
    # The prePatch CMake rewrite disables the download of this file, so the
    # derivation supplies it instead.
    modern_bpf_c = fetchurl {
      url = "https://raw.githubusercontent.com/wazuh/wazuh/v${version}/src/syscheckd/src/ebpf/src/modern.bpf.c";
      hash = "sha256-YZBikwlQrNS65WEUzOxd78L32nM5D+Bwdbq+MfW1OL0=";
    };
  };
in
{
  inherit version dependencyVersion wazuhRev wazuhSrc wazuh-http-request libbpf_bootstrap_deps external_dependencies;
}
