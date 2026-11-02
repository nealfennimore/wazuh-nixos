# The manager cluster in two VMs. Run it with:
#
#   nix build .#checks.x86_64-linux.server-cluster
#
# Scope: wazuh-clusterd runs on a master and a worker that share a key from
# a root-only file. The worker connects, cluster_control on the master
# lists both nodes, and a group file written on the master reaches the
# worker through the integrity sync. The key is in the installed ossec.conf
# and not in the Nix store, and a key that clusterd would refuse stops the
# setup unit.
{
  pkgs,
  wazuhServerModule,
}:
let
  key = "0123456789abcdefABCDEF0123456789";
  node =
    name: type:
    { ... }:
    {
      imports = [ wazuhServerModule ];
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 4096;
      services.wazuh-server = {
        enable = true;
        openFirewall = true;
        cluster = {
          nodeName = name;
          nodeType = type;
          keyFile = "/run/secrets/wazuh-cluster-key";
          nodes = [ "master" ];
        };
      };
      systemd.tmpfiles.rules = [ "f /run/secrets/wazuh-cluster-key 0400 root root - ${key}" ];
    };
  control = "cd /var/ossec && runuser -u wazuh -- env WAZUH_HOME=/var/ossec /var/ossec/framework/python/bin/python3 /var/ossec/framework/scripts/cluster_control.py";
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-cluster";
  globalTimeout = 2 * 3600;

  nodes.master = node "master-node" "master";
  nodes.worker = node "worker-node" "worker";

  testScript = ''
    start_all()

    with subtest("clusterd runs on both nodes"):
        for machine in [master, worker]:
            machine.wait_for_unit("wazuh-clusterd.service", timeout=1200)
        master.wait_until_succeeds("ss -Hltn 'sport = :1516' | grep -q LISTEN", timeout=600)

    with subtest("the worker joins the master"):
        master.wait_until_succeeds("${control} -l | grep -q worker-node", timeout=900)
        print(master.succeed("${control} -l"))

    with subtest("a group file on the master reaches the worker"):
        master.succeed("printf '<agent_config><!-- cluster sync test --></agent_config>\\n' > /var/ossec/etc/shared/default/agent.conf")
        master.succeed("chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf")
        worker.wait_until_succeeds("grep -q 'cluster sync test' /var/ossec/etc/shared/default/agent.conf", timeout=600)

    with subtest("the key is installed and not in the store"):
        for machine in [master, worker]:
            machine.succeed("grep -qF '<key>${key}</key>' /var/ossec/etc/ossec.conf")
            machine.succeed("grep -qF '@WAZUH_SECRET_cluster-key@' /nix/store/*-ossec.conf")
            machine.fail("grep -rqF -- '${key}' /nix/store/*-ossec.conf")

    with subtest("a key that clusterd would refuse stops setup"):
        worker.succeed("printf '%s\\n' 'too-short' > /run/secrets/wazuh-cluster-key")
        worker.fail("systemctl restart wazuh-server-setup.service")
        worker.succeed("journalctl -u wazuh-server-setup.service | grep -q 'secret cluster-key does not match'")
        worker.succeed("grep -qF '<key>${key}</key>' /var/ossec/etc/ossec.conf")
  '';
}
