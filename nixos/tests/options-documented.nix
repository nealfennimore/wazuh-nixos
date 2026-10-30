# Every option of the four modules must appear in the documentation.
#
# The agent and server options are documented in README.md, the indexer and
# dashboard options in their module READMEs. This check evaluates each module
# the way a host does, lists its options, and fails when a leaf option name is
# missing from its README. A container option (a submodule) counts as
# documented when any of its children is. Option names are matched as
# `name` in backticks, relative to the services.<module> prefix, so
# `api.tls.key` documents services.wazuh-server.api.tls.key. The placeholder
# <name> is kept as written.
{
  pkgs,
  nixpkgs,
  modules,
  readmes,
}:
let
  lib = pkgs.lib;
  system = pkgs.stdenv.hostPlatform.system;
  host = module:
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        module
        {
          nixpkgs.hostPlatform = system;
          boot.loader.grub.enable = false;
          fileSystems."/".device = "none";
          system.stateVersion = "25.11";
        }
      ];
    }).options;
  optionNames = prefix: module:
    map (o: lib.removePrefix "services.${prefix}." o.name) (
      lib.filter (o: !(o.internal or false) && (o.visible or true) != false) (
        lib.optionAttrSetToDocList (lib.getAttrFromPath [ "services" prefix ] (host module))
      )
    );
  spec = lib.mapAttrs (prefix: module: {
    readme = readmes.${prefix};
    options = optionNames prefix module;
  }) modules;
in
pkgs.runCommand "wazuh-options-documented"
  {
    nativeBuildInputs = [ pkgs.jq ];
    spec = builtins.toJSON spec;
    passAsFile = [ "spec" ];
  }
  ''
    status=0
    for module in $(jq -r 'keys[]' "$specPath"); do
      readme=$(jq -r --arg m "$module" '.[$m].readme' "$specPath")
      all=$(jq -r --arg m "$module" '.[$m].options[]' "$specPath")
      for name in $all; do
        if grep -qF -- "\`$name\`" "$readme"; then
          continue
        fi
        # A container is documented when one of its children is.
        if printf '%s\n' "$all" | grep -qF -- "$name." && \
           printf '%s\n' "$all" | grep -F -- "$name." | while read -r child; do
             grep -qF -- "\`$child\`" "$readme" && exit 0
           done; then
          continue
        fi
        echo "services.$module.$name is not documented in ${"$"}{readme##*/}"
        status=1
      done
    done
    test $status = 0
    touch "$out"
  ''
