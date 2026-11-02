# The manager cluster in two VMs. Run it with:
#
#   nix build .#checks.x86_64-linux.server-cluster
#
# Scope: wazuh-clusterd runs on a master and a worker that share a key from
# a root-only file. The worker connects, cluster_control on the master
# lists both nodes, and a group file written on the master reaches the
# worker through the integrity sync. The key is in the installed ossec.conf
# and not in the Nix store, and a key that clusterd would refuse stops the
# setup unit. The master carries a disabled haproxy_helper with every field
# set: the framework's own reader parses it, its password and certificates
# come from root-only files, and a password with a comma stops setup.
#
# It does not run the helper against an HAProxy Data Plane API.
{
  pkgs,
  wazuhServerModule,
}:
let
  key = "0123456789abcdefABCDEF0123456789";
  haproxyPassword = "Haproxy-Pw-4242";
  pki = import ../common/pki.nix { inherit pkgs; };
  node =
    name: type: extra:
    { lib, ... }:
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
        }
        // extra;
      };
      systemd.tmpfiles.rules = [
        "f /run/secrets/wazuh-cluster-key 0400 root root - ${key}"
        "f /run/secrets/wazuh-haproxy-password 0400 root root - ${haproxyPassword}"
      ];
    };
  control = "cd /var/ossec && runuser -u wazuh -- env WAZUH_HOME=/var/ossec /var/ossec/framework/python/bin/python3 /var/ossec/framework/scripts/cluster_control.py";
in
pkgs.testers.runNixOSTest {
  name = "wazuh-server-cluster";
  globalTimeout = 2 * 3600;

  nodes.master = node "master-node" "master" {
    haproxyHelper = {
      enable = false;
      address = "haproxy";
      protocol = "https";
      user = "dataplane";
      passwordFile = "/run/secrets/wazuh-haproxy-password";
      caFile = pki.ca;
      clientCertFile = pki.server.cert;
      clientKeyFile = pki.server.key;
      excludedNodes = [
        "worker-a"
        "worker-b"
      ];
      frequency = 30;
      agentChunkSize = 150;
      imbalanceTolerance = "0.2";
    };
  };
  nodes.worker = node "worker-node" "worker" { };

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

    with subtest("the framework parses the haproxy_helper and its files are installed"):
        parsed = master.succeed(
            "cd /var/ossec && runuser -u wazuh -- env WAZUH_HOME=/var/ossec"
            + " /var/ossec/framework/python/bin/python3 -c"
            + " 'import json; from wazuh.core.cluster.utils import read_cluster_config;"
            + " print(json.dumps(read_cluster_config()[\"haproxy_helper\"], default=str))'"
        )
        print(parsed)
        import json
        helper = json.loads(parsed.strip().splitlines()[-1])
        assert helper["haproxy_disabled"] is True, helper
        assert helper["haproxy_password"] == "${haproxyPassword}", helper
        assert helper["haproxy_protocol"] == "https", helper
        assert helper["excluded_nodes"] == ["worker-a", "worker-b"], helper
        assert helper["frequency"] == 30 and helper["agent_chunk_size"] == 150, helper
        assert helper["imbalance_tolerance"] == 0.2, helper
        for name in ["haproxy_cert", "client_cert", "client_cert_key"]:
            master.succeed(f"test -s {helper[name]} && test \"$(stat -c %G {helper[name]})\" = wazuh")
        master.fail("grep -rqF -- '${haproxyPassword}' /nix/store/*-ossec.conf")
        master.succeed("systemctl is-active wazuh-clusterd.service")

    with subtest("a haproxy password with a comma stops setup"):
        master.succeed("printf '%s\\n' 'bad,password' > /run/secrets/wazuh-haproxy-password")
        master.fail("systemctl restart wazuh-server-setup.service")
        master.succeed("journalctl -u wazuh-server-setup.service | grep -q 'secret cluster-haproxy-password does not match'")
        master.succeed("grep -qF '${haproxyPassword}' /var/ossec/etc/ossec.conf")

    with subtest("a key that clusterd would refuse stops setup"):
        worker.succeed("printf '%s\\n' 'too-short' > /run/secrets/wazuh-cluster-key")
        worker.fail("systemctl restart wazuh-server-setup.service")
        worker.succeed("journalctl -u wazuh-server-setup.service | grep -q 'secret cluster-key does not match'")
        worker.succeed("grep -qF '<key>${key}</key>' /var/ossec/etc/ossec.conf")
  '';
}
