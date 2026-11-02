# Exercise structured XML through Wazuh's own readers and real collectors.
{ pkgs, wazuhServerModule }:
pkgs.testers.runNixOSTest {
  name = "wazuh-server-config";
  globalTimeout = 1800;
  nodes.server = { config, lib, pkgs, ... }: {
    imports = [ wazuhServerModule ];
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    services.wazuh-server = {
      enable = true;
      logAll = true;
      settings = lib.recursiveUpdate (import ../../../examples/server/monitoring.nix) {
        global = {
          logall = true;
          logall_json = true;
        };
        # Exercise scan completion quickly rather than scanning the VM store.
        syscheck.directories = [ "/etc/wazuh-fixture" ];
        # ReadActiveResponses resolves command names immediately; this must
        # be rendered after the generated command definitions. Level 16
        # keeps the response from running for this test's ordinary events.
        active-response = [
          {
            command = "firewall-drop";
            location = "local";
            level = 16;
            timeout = 60;
          }
        ];
        localfile = [
          {
            log_format = "journald";
            location = "journald";
          }
          {
            log_format = "syslog";
            location = "/var/ossec/logs/active-responses.log";
          }
          {
            log_format = "command";
            command = "echo structured-command-marker";
            frequency = 10;
          }
        ];
      };
      path = [
        pkgs.coreutils
        pkgs.procps
      ];
    };
    users.users.wazuh.extraGroups = [ "systemd-journal" ];
    # Model the older layout that linked etc to the immutable package.
    # Setup must replace the link before installing rootcheck data.
    systemd.services.wazuh-legacy-layout = {
      requiredBy = [ "wazuh-server-setup.service" ];
      before = [ "wazuh-server-setup.service" ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        install -d /var/ossec
        ln -s ${config.services.wazuh-server.package}/etc /var/ossec/etc
        touch /run/wazuh-legacy-layout-planted
      '';
    };
    environment.etc."wazuh-fixture/canary".text = "initial content";
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = ''
    start_all()
    with subtest("setup migrates the old store-linked etc directory"):
        server.wait_for_unit("wazuh-legacy-layout.service")
        server.succeed("test -e /run/wazuh-legacy-layout-planted")
        server.succeed("systemctl start wazuh-server-setup.service")
        server.succeed("test -d /var/ossec/etc && test ! -L /var/ossec/etc")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/etc) = root:wazuh:1770")
    server.wait_for_unit("wazuh-server.target")
    for daemon in ["db", "analysisd", "remoted", "syscheckd", "logcollector", "modulesd"]:
        server.wait_for_unit(f"wazuh-{daemon}.service")

    with subtest("merged configuration has one value and preserves attributed elements"):
        server.succeed("""python3 - <<'PY'
    import xml.etree.ElementTree as ET
    root = ET.parse('/var/ossec/etc/ossec.conf').getroot()
    assert len(root.findall('global')) == 1
    assert root.findtext('global/agents_disconnection_time') == '10m'
    assert root.findtext('global/jsonout_output') == 'yes'
    assert root.findall('global/white_list')[-1].text == '127.0.0.53'
    assert root.find('syscheck/auto_ignore').attrib == {'frequency': '10', 'timeframe': '3600'}
    assert root.find('syscheck/auto_ignore').text == 'no'
    assert root.find("syscheck/ignore[@type='sregex']").text == '.log$|.swp$'
    assert root.find("wodle[@name='syscollector']/ports").attrib == {'all': 'no'}
    assert len(root.findall('wodle')) == 3
    assert len(root.findall('localfile')) == 3
    assert root.findtext('cluster/disabled') == 'yes'
    sections = [element.tag for element in root]
    assert sections.index('command') < sections.index('active-response')
    PY""")
        server.succeed("test -s /var/ossec/etc/rootcheck/rootkit_files.txt")
        server.succeed("test -s /var/ossec/etc/rootcheck/rootkit_trojans.txt")
        for daemon in ["analysisd", "syscheckd", "logcollector", "modulesd"]:
            server.succeed(f"cd /var/ossec && WAZUH_HOME=/var/ossec ./bin/wazuh-{daemon} -t")

    with subtest("enabled scans finish under the server sandbox"):
        for unit, line in [
            ("wazuh-modulesd", "syscollector: INFO: Evaluation finished"),
            ("wazuh-modulesd", "sca: INFO: Evaluation finished"),
            ("wazuh-syscheckd", "rootcheck: INFO: Ending rootcheck scan"),
            ("wazuh-syscheckd", "(6009): File integrity monitoring scan ended"),
        ]:
            server.wait_until_succeeds(f"journalctl -u {unit} | grep -Fq '{line}'", timeout=600)

    with subtest("journald and command collectors deliver events to analysisd"):
        server.succeed("logger -t wazuh-config-test structured-journal-marker")
        for marker in ["structured-journal-marker", "structured-command-marker"]:
            server.wait_until_succeeds(
                f"grep -q '{marker}' /var/ossec/logs/archives/archives.json", timeout=120
            )
        server.fail("journalctl -b | grep -E 'status=31/SYS|code=killed, status=SYS'")
  '';
}
