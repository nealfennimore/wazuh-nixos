# Representation checks and module assertions, independent of VM boot.
{
  pkgs,
  nixpkgs,
  wazuhServerModule,
}:
let
  inherit (pkgs) lib;
  xml = import ../../wazuh-server/xml.nix { inherit lib; };
  fails = value: !(builtins.tryEval (builtins.deepSeq value value)).success;
  hostConfig =
    options:
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        wazuhServerModule
        ({ lib, ... }: {
          options.services.wazuh-agent.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          config.services.wazuh-agent.enable = options._agent or false;
        })
        {
          services.wazuh-server = {
            enable = true;
          }
          // builtins.removeAttrs options [ "_agent" ];
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config;
  assertionCases = import ./assertion-cases.nix;
  # The <ruleset> section that a host with these options gets.
  rulesetOf =
    options:
    let
      text = (
        import ../../wazuh-server/generate-server-config.nix {
          inherit pkgs;
          cfg = (hostConfig options).services.wazuh-server;
          credentialPaths = { };
        }
      ).text;
    in
    builtins.elemAt (builtins.match ".*<ruleset>(.*)</ruleset>.*" text) 0;
  checksAssertion =
    case:
    let
      assertions = (hostConfig case.options).assertions;
    in
    if lib.any (a: !a.assertion && lib.hasInfix case.diagnostic a.message) assertions then
      true
    else
      throw "Missing expected assertion: ${case.diagnostic}";
  rejected = settings: lib.any (a: !a.assertion) (hostConfig { inherit settings; }).assertions;
  references =
    overrides:
    import ../../wazuh-server/settings-runtime.nix {
      inherit lib;
      cfg = {
        settings = { };
        auth.settings = { };
        secretFiles = {
          token = "/run/secrets/token";
        };
        credentialFiles = {
          google = "/run/secrets/google.json";
        };
      }
      // overrides;
    };
  disabledResponse = hostConfig {
    activeResponse.enable = false;
    settings.active-response = [
      {
        command = "firewall-drop";
        location = "local";
        level = 16;
      }
    ];
  };
  example =
    (nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        wazuhServerModule
        ../../../examples/server-parity.nix
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config;
  exampleConfig = import ../../wazuh-server/generate-server-config.nix {
    inherit pkgs;
    cfg = example.services.wazuh-server;
    credentialPaths = {
      indexerCa = "/var/ossec/etc/indexer-ca.pem";
      indexerCertificate = "/var/ossec/etc/indexer.pem";
      indexerKey = "/var/ossec/etc/indexer.key";
      authAgentCa = "/var/ossec/etc/agent-ca.pem";
    };
  };
in
assert lib.all checksAssertion assertionCases;
assert lib.all (a: a.assertion) (hostConfig { }).assertions;
assert
  xml.render {
    a = [
      true
      false
      12
      "x&y"
    ];
    b = null;
  } == "<a>yes</a>\n<a>no</a>\n<a>12</a>\n<a>x&y</a>\n";
assert
  xml.render {
    ports = {
      _attributes.all = false;
      _text = true;
    };
  } == "<ports all=\"no\">yes</ports>\n";
assert fails (xml.render { value = "<injection>"; });
assert fails (xml.render { value = "trailing\\"; });
assert fails (xml.render { "invalid tag" = "x"; });
assert fails (
  xml.render {
    value = {
      _attributes.key = "\"";
      _text = "x";
    };
  }
);
assert fails (
  xml.render {
    value = {
      _text = "x";
      child = "y";
    };
  }
);
# Declared ruleset files. Without them the <ruleset> section is the default.
# With them the declared directories come last, also when settings.ruleset
# replaces the directory lists. The position has no effect on the load order.
assert rulesetOf { } == rulesetOf { ruleset = { }; };
assert !(lib.hasInfix "/declared" (rulesetOf { }));
assert lib.hasInfix "<rule_dir>etc/rules</rule_dir>\n<rule_dir>etc/rules/declared</rule_dir>\n" (rulesetOf {
  ruleset.rules."local_rules.xml".text = "x";
});
assert !(lib.hasInfix "etc/decoders/declared" (rulesetOf { ruleset.rules."local_rules.xml".text = "x"; }));
assert lib.hasInfix "<decoder_dir>etc/decoders</decoder_dir>\n<decoder_dir>etc/decoders/declared</decoder_dir>\n" (rulesetOf {
  ruleset.decoders."local_decoder.xml".text = "x";
});
assert lib.hasInfix "<list>etc/lists/malicious-ioc/malicious-domains</list>\n<list>etc/lists/declared/a</list>\n<list>etc/lists/declared/b</list>\n" (rulesetOf {
  ruleset.lists.b.text = "x";
  ruleset.lists.a.text = "x";
});
assert lib.hasInfix "<rule_dir>custom/rules</rule_dir>\n<rule_dir>etc/rules/declared</rule_dir>\n" (rulesetOf {
  settings.ruleset.rule_dir = "custom/rules";
  ruleset.rules."local_rules.xml".text = "x";
});
assert rejected { remote.port = 514; };
assert (references { }).resolve { _secret = "token"; } == "@WAZUH_SECRET_settings-token@";
assert (references { }).resolve { _credential = "google"; } == "/var/ossec/etc/credentials/google";
assert fails ((references { }).resolve { _secret = "missing"; });
assert fails ((references { }).resolve { _credential = "missing"; });
assert fails (
  (references { }).resolve {
    _secret = "token";
    child = "bad";
  }
);
assert fails ((references { }).resolve { _attributes.key._secret = "token"; });
assert fails (references { settings.wodle.password._secret = "token"; }).settings;
assert fails (references { settings.localfile.command._secret = "token"; }).settings;
assert
  (references { settings.office365.api_auth.client_secret._secret = "token"; }).secrets == {
    settings-token = {
      source = "/run/secrets/token";
      target = "config";
    };
  };
assert rejected { global.email_notification = true; };
assert rejected { cluster.disabled = false; };
assert rejected { vulnerability-detection.enabled = true; };
assert lib.any (a: !a.assertion) disabledResponse.assertions;
assert lib.all (a: a.assertion) example.assertions;
pkgs.runCommand "wazuh-server-config-eval"
  { nativeBuildInputs = [ pkgs.python3 ] ++ example.services.wazuh-server.path; }
  ''
    for command in df netstat sed sort last; do command -v "$command"; done
    python3 - ${exampleConfig} <<'PY'
    import sys
    import xml.etree.ElementTree as ET
    root = ET.parse(sys.argv[1]).getroot()
    assert len(root.findall('remote')) == 2
    assert root.findtext("remote[connection='syslog']/port") == '514'
    assert root.findtext('global/agents_disconnection_time') == '10m'
    assert len(root.findall('global')) == 1
    assert len(root.findall('integration')) == 2
    assert root.findtext('github/api_auth/org_name') == 'xnor-software'
    assert root.findtext('github/api_auth/api_token').startswith('@WAZUH_SECRET_')
    assert root.findtext('indexer/enabled') == 'yes'
    assert root.findtext('vulnerability-detection/enabled') == 'yes'
    assert root.findtext('auth/use_password') == 'yes'
    assert root.findtext('syscheck/auto_ignore') == 'no'
    assert root.find("wodle[@name='syscollector']/ports").get('all') == 'no'
    assert root.findtext("localfile[location='journald']/log_format") == 'journald'
    PY
    touch "$out"
  ''
