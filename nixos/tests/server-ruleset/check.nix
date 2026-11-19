# The build-time check of the declared ruleset. Run it with:
#
#   nix build .#checks.x86_64-linux.server-ruleset-check
#
# No VM. A good ruleset passes nixos/wazuh-server/ruleset-check.nix, and the
# module puts that derivation in system.checks. Each bad ruleset fails the
# derivation with the message of wazuh-analysisd. The module leaves the
# check out when validate is off, when no file is declared, and when a
# source is a host file.
{
  pkgs,
  nixpkgs,
  wazuhServerModule,
}:
let
  inherit (pkgs) lib;
  host =
    ruleset:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        wazuhServerModule
        {
          services.wazuh-server = {
            enable = true;
            inherit ruleset;
          };
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config;
  checksOf = ruleset: lib.filter (c: c.name == "wazuh-server-ruleset-check") (host ruleset).system.checks;
  check = ruleset: builtins.head (checksOf ruleset);

  group = body: ''
    <group name="local,">
    ${body}
    </group>
  '';
  rule = body: group ''
    <rule id="100100" level="5">
      ${body}
      <description>Test rule.</description>
    </rule>
  '';
  good = {
    decoders."local_decoder.xml".text = ''
      <decoder name="check-app">
        <prematch>^check-app: </prematch>
      </decoder>
    '';
    rules."local_rules.xml".text = rule ''
      <decoded_as>check-app</decoded_as>
      <list field="user" lookup="match_key">etc/declared/lists/users</list>
    '';
    lists.users.text = ''
      mallory:blocked
    '';
  };
  bad = {
    unclosed = {
      ruleset.rules."local_rules.xml".text = "<group name=\"local,\"><rule id=\"100100\" level=\"5\"><match>x</match><description>x</description></rule>";
      message = "Error reading XML file 'etc/declared/rules/local_rules.xml'";
    };
    unknown-decoder = {
      ruleset.rules."local_rules.xml".text = rule "<decoded_as>no-such-decoder</decoded_as>";
      message = "Invalid decoder name: 'no-such-decoder'";
    };
    missing-list = {
      ruleset.rules."local_rules.xml".text = rule ''
        <match>x</match>
        <list field="user" lookup="match_key">etc/declared/lists/missing</list>
      '';
      message = "List 'etc/declared/lists/missing' could not be loaded";
    };
    bad-decoder = {
      ruleset.decoders."local_decoder.xml".text = "<decoder name=\"check-app\"><parent>no-such-parent</parent><regex>x</regex></decoder>";
      message = "etc/declared/decoders/local_decoder.xml";
    };
    # The name does not end in _rules.xml. A file that the manager skipped
    # would pass.
    other-name = {
      ruleset.rules."other.xml".text = rule "<decoded_as>no-such-decoder</decoded_as>";
      message = "Error loading the rules: 'etc/declared/rules/other.xml'";
    };
  };
  refused = lib.mapAttrs (
    name: case:
    pkgs.runCommand "wazuh-server-ruleset-refused-${name}"
      { failed = pkgs.testers.testBuildFailure (check case.ruleset); }
      ''
        grep -F "services.wazuh-server.ruleset: wazuh-analysisd does not accept" "$failed/testBuildFailure.log"
        grep -F ${lib.escapeShellArg case.message} "$failed/testBuildFailure.log"
        touch "$out"
      ''
  ) bad;
in
assert lib.length (checksOf good) == 1;
assert checksOf { } == [ ];
assert checksOf (good // { validate = false; }) == [ ];
assert
  checksOf (
    good
    // {
      lists.users = {
        source = "/etc/wazuh-users";
      };
    }
  ) == [ ];
pkgs.runCommand "wazuh-server-ruleset-check-test" { } ''
  echo ${check good} ${toString (builtins.attrValues refused)}
  touch "$out"
''
