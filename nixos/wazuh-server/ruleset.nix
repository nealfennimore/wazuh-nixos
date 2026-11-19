# services.wazuh-server.ruleset: rules, decoders and CDB lists declared in
# the configuration.
#
# The stock ruleset is ruleset/ from the package. etc/rules, etc/decoders and
# etc/lists belong to the host: the API and the dashboard editor write them,
# and the module does not change them after their first copy. The files
# declared here go to a subdirectory of each, which only root writes:
#
#   etc/rules/declared
#   etc/decoders/declared
#   etc/lists/declared
#
# They are below the host directories because the API finds a file only
# there: its access control walks ruleset/rules and etc/rules, and the same
# for decoders and lists (wazuh/rbac/utils.py, expand_rules). A file in
# another place loads in analysisd but is absent from the API and the
# dashboard.
#
# The setup unit synchronizes each subdirectory, so a file removed from the
# configuration leaves the host. A read-only mount in the units of the API
# and of clusterd keeps them from a change of a declared file. analysisd
# compiles each CDB list beside its source (src/analysisd/lists_make.c) and
# can write etc/lists.
#
# default.nix installs the tree (the setup unit) and
# generate-server-config.nix adds the directories to <ruleset>.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.wazuh-server;

  file = kind: {
    options = {
      text = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = "Content of the ${kind}. Set this or `source`.";
      };
      source = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          File with the content of the ${kind}. Set this or `text`. A Nix
          path literal is copied to the store at build time. A string names
          a file on the host that the setup unit reads at each activation.
        '';
      };
    };
  };

  files =
    kind: example:
    mkOption {
      type = types.attrsOf (types.submodule (file kind));
      default = { };
      inherit example;
    };

  kinds = [
    "rules"
    "decoders"
    "lists"
  ];

  entries =
    kind:
    lib.mapAttrsToList (name: value: {
      name = "${kind}/${name}";
      path = if value.source != null then value.source else pkgs.writeText name value.text;
    }) cfg.ruleset.${kind};

  # A directory for each kind is always present, so the setup unit needs no
  # case for an empty kind.
  tree = pkgs.runCommand "wazuh-server-declared-ruleset" { } ''
    mkdir -p $out/rules $out/decoders $out/lists
    cp -R --no-dereference ${pkgs.linkFarm "wazuh-server-declared-ruleset-links" (lib.concatMap entries kinds)}/. $out/
  '';

  validName = builtins.match "[A-Za-z0-9_][A-Za-z0-9_.-]*";
  names = kind: builtins.attrNames cfg.ruleset.${kind};
in
{
  options.services.wazuh-server.ruleset = {
    rules = files "rule file" {
      "local_rules.xml".text = ''
        <group name="local,">
          <rule id="100100" level="5">
            <decoded_as>example</decoded_as>
            <description>Example event.</description>
          </rule>
        </group>
      '';
    }
    // {
      description = ''
        Rule files, by file name. The setup unit installs them in
        `/var/ossec/etc/rules/declared`, and the generated `ossec.conf`
        loads that directory. `wazuh-analysisd` loads the rule files of all
        directories in the order of their file names, so a file must sort
        after each file whose rules it uses in `if_sid`. Use
        rule identifiers from 100000 to 120000, as upstream requires for
        custom rules. A name must end in `.xml`.
      '';
    };

    decoders = files "decoder file" (lib.literalExpression ''{ "local_decoder.xml".source = ./local_decoder.xml; }'')
    // {
      description = ''
        Decoder files, by file name. The setup unit installs them in
        `/var/ossec/etc/decoders/declared`, and the generated `ossec.conf`
        loads that directory. The file name sets the load order, as for
        rules.
        A name must end in `.xml`.
      '';
    };

    lists = files "CDB list" {
      "blocked-users".text = ''
        mallory:
        trudy:
      '';
    }
    // {
      description = ''
        CDB lists, by file name, with one `key:value` on each line. The
        setup unit installs them in `/var/ossec/etc/lists/declared`, and
        the generated `ossec.conf` has one `<list>` for each. A rule refers
        to a list as `etc/lists/declared/<name>`. A name must not end in
        `.cdb`.
      '';
    };

    validate = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Load the declared files with `wazuh-analysisd -t` at build time,
        together with the stock ruleset and the generated `ossec.conf`. An
        error or a warning fails the build. The check does not run when a
        `source` names a host file, because a build cannot read it.
      '';
    };

    buildTimeSources = mkOption {
      type = types.bool;
      internal = true;
      readOnly = true;
      default = lib.all (
        kind:
        lib.all (
          value:
          value.text != null
          || builtins.isPath value.source
          || lib.hasPrefix builtins.storeDir (toString value.source)
        ) (builtins.attrValues cfg.ruleset.${kind})
      ) kinds;
      description = "True when a build can read every declared file.";
    };

    tree = mkOption {
      type = types.package;
      internal = true;
      readOnly = true;
      default = tree;
      description = "The declared files, as the setup unit installs them.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (kind: lib.all (name: validName name != null) (names kind)) kinds;
        message = "services.wazuh-server.ruleset: a file name may contain only letters, digits, underscore, hyphen and period, and cannot start with a hyphen or a period.";
      }
      {
        assertion = lib.all (lib.hasSuffix ".xml") (names "rules" ++ names "decoders");
        message = "services.wazuh-server.ruleset: the name of a rule file or a decoder file must end in .xml. The module loads only such files from the directory.";
      }
      {
        assertion = lib.all (name: !(lib.hasSuffix ".cdb" name)) (names "lists");
        message = "services.wazuh-server.ruleset.lists: a name cannot end in .cdb. The manager writes the compiled list to that name.";
      }
      {
        assertion = lib.all (
          kind: lib.all (value: (value.text == null) != (value.source == null)) (builtins.attrValues cfg.ruleset.${kind})
        ) kinds;
        message = "services.wazuh-server.ruleset: set exactly one of text and source for each file.";
      }
    ];
  };
}
