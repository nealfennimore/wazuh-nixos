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
        {
          services.wazuh-server = {
            enable = true;
          }
          // options;
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config;
  rejected = settings: lib.any (a: !a.assertion) (hostConfig { inherit settings; }).assertions;
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
assert rejected { remote.port = 514; };
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
