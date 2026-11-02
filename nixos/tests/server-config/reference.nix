# Exercise newly exposed native sections and runtime-only credential references.
{ pkgs, wazuhServerModule }:
pkgs.testers.runNixOSTest {
  name = "wazuh-server-reference";
  globalTimeout = 1200;
  nodes.server = { lib, ... }: {
    imports = [ wazuhServerModule ];
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    services.wazuh-server = {
      enable = true;
      secretFiles.microsoft = "/run/reference-secret";
      credentialFiles.google = "/run/reference-credential";
      integrations.custom-reference = {
        level = 3;
      };
      integrationScripts.custom-reference = pkgs.writeText "custom-reference.py" ''
        import json, sys
        from pathlib import Path
        alert = json.loads(Path(sys.argv[1]).read_text())
        if str(alert.get("rule", {}).get("id")) == "5710":
            Path("/var/ossec/logs/custom-reference-delivered").write_text("delivered")
      '';
      auth.settings = {
        use_source_ip = true;
        purge = false;
      };
      settings = {
        localfile = [
          {
            location = "/var/log/reference-auth.log";
            log_format = "syslog";
          }
        ];
        task-manager = {
          cleanup_time = "2d";
          task_timeout = "1h";
        };
        wdb.backup = {
          _attributes.database = "global";
          enabled = true;
          interval = "1d";
          max_files = 3;
        };
        office365 = {
          enabled = false;
          interval = "1m";
          api_auth = {
            tenant_id = "test-tenant";
            client_id = "test-client";
            client_secret._secret = "microsoft";
            api_type = "commercial";
          };
          subscriptions.subscription = [ "Audit.General" ];
        };
        ms-graph = {
          enabled = false;
          interval = "5m";
          version = "v1.0";
          api_auth = {
            tenant_id = "test-tenant";
            client_id = "test-client";
            secret_value._secret = "microsoft";
            api_type = "global";
          };
          resource = {
            name = "security";
            relationship = [ "alerts_v2" ];
          };
        };
        gcp-pubsub = {
          enabled = false;
          project_id = "test-project";
          subscription_name = "test-subscription";
          credentials_file._credential = "google";
        };
      };
    };
    systemd.services.reference-credentials = {
      before = [ "wazuh-server-setup.service" ];
      requiredBy = [ "wazuh-server-setup.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        umask 077
        touch /var/log/reference-auth.log
        chmod 0644 /var/log/reference-auth.log
        printf 'reference-runtime-token' > /run/reference-secret
        printf '{"fixture": "opaque file with spaces"}\n' > /run/reference-credential
      '';
    };
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = { nodes, ... }: ''
    start_all()
    server.wait_for_unit("wazuh-server.target")
    with subtest("native readers accept the additional sections"):
        for daemon in ["analysisd", "modulesd", "authd", "db"]:
            server.succeed(f"cd /var/ossec && WAZUH_HOME=/var/ossec ./bin/wazuh-{daemon} -t")
    with subtest("credentials are installed at runtime with restrictive ownership"):
        server.succeed("cmp /run/reference-credential /var/ossec/etc/credentials/google")
        server.succeed("test $(stat -c %U:%G:%a /var/ossec/etc/credentials/google) = root:wazuh:640")
        server.succeed("grep -q reference-runtime-token /var/ossec/etc/ossec.conf")
        setup = "${nodes.server.systemd.services.wazuh-server-setup.serviceConfig.ExecStart}"
        server.succeed(f"grep -o '/nix/store/[^ ]*-ossec.conf' {setup} | head -1 > /tmp/config-path")
        server.fail("grep -q reference-runtime-token $(cat /tmp/config-path)")
        server.succeed("grep -q @WAZUH_SECRET_settings-microsoft@ $(cat /tmp/config-path)")
    with subtest("custom Python integration receives a real alert"):
        server.wait_for_unit("wazuh-integratord.service")
        server.wait_for_unit("wazuh-logcollector.service")
        server.succeed("echo 'Nov  2 22:00:00 server sshd[123]: Invalid user reference-test from 192.0.2.4 port 12345' >> /var/log/reference-auth.log")
        server.wait_until_succeeds("test -f /var/ossec/logs/custom-reference-delivered", timeout=120)
    with subtest("cloud code remains immutable and Azure state uses the writable tree"):
        server.succeed("test ! -L /var/ossec/wodles")
        server.fail("runuser -u wazuh -- test -w /var/ossec/wodles/azure/db/orm.py")
        server.succeed("""cd /var/ossec && runuser -u wazuh -- ./framework/python/bin/python3 - <<'PY'
    import sys
    sys.path.insert(0, '/var/ossec/wodles/azure')
    from db import orm
    orm.Base.metadata.create_all(orm.engine)
    PY""")
        server.succeed("test -f /var/ossec/var/wodles/azure/azure.db")
        server.fail("test -e /var/ossec/wodles/azure/azure.db")
        server.succeed("""cd /var/ossec && runuser -u wazuh -- ./framework/python/bin/python3 - <<'PY'
    import sys
    from unittest.mock import patch
    sys.path.insert(0, '/var/ossec/wodles/aws')
    from wazuh_integration import WazuhAWSDatabase, WazuhIntegration
    with patch.object(WazuhIntegration, 'get_client'):
        database = WazuhAWSDatabase('fixture', 'fixture', None, None, 'reference', service_name='s3', region='us-east-1')
    assert database.db_path == '/var/ossec/var/wodles/aws/reference.db'
    database.db_connector.close()
    PY""")
        server.succeed("""cd /var/ossec && runuser -u wazuh -- ./framework/python/bin/python3 - <<'PY'
    import sys, logging
    from unittest.mock import patch, Mock
    sys.path.insert(0, '/var/ossec/wodles/gcloud')
    from buckets.bucket import WazuhGCloudBucket
    with patch('google.cloud.storage.client.Client.from_service_account_json', return_value=Mock(project='fixture')):
        database = WazuhGCloudBucket('/var/ossec/etc/credentials/google', logging.getLogger('fixture'), 'fixture')
    assert database.db_path == '/var/ossec/var/wodles/gcloud/gcloud.db'
    database.db_table_name = 'reference'
    database.init_db()
    database.db_connector.close()
    PY""")
  '';
}
