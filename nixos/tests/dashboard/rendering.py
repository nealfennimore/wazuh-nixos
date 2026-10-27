"""Boundary tests for credential serialization and fail-closed TLS patching."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

CONFIGURE, USERS, PATCH = sys.argv[1:4]
sys.argv = sys.argv[:1]

class Rendering(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.creds = self.root / "credentials"
        self.creds.mkdir()
        self.env = dict(os.environ, CREDENTIALS_DIRECTORY=str(self.creds))

    def run_script(self, script, *args, success=True):
        result = subprocess.run([sys.executable, script, *map(str, args)], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode == 0, success, result.stderr.decode())
        return result

    def test_dashboard_credentials_and_multiple_cas(self):
        password = 'quotes" colon: dollar$ backslash\\ unicode-é'
        for name, value in {"indexer-username": "kibanaserver", "indexer-password": password,
                            "manager-0-username": "wui", "manager-0-password": password,
                            "manager-1-username": "wui2", "manager-1-password": "secret2",
                            "manager-0-ca": "CA ONE\n", "manager-1-ca": "CA TWO\n"}.items():
            (self.creds / name).write_text(value)
        spec = self.root / "spec.json"
        spec.write_text(json.dumps({"settings": {}, "managers": [
            {"id": f"manager-{i}", "url": f"https://server{i}", "port": 55000, "runAs": False}
            for i in range(2)]}))
        self.run_script(CONFIGURE, spec, self.root, self.root / "state")
        settings = json.loads((self.root / "opensearch_dashboards.yml").read_text())
        self.assertEqual(settings["opensearch.password"], password)
        hosts = json.loads((self.root / "state/wazuh/config/wazuh.yml").read_text())["hosts"]
        self.assertEqual(hosts[0]["manager-0"]["password"], password)
        self.assertEqual(hosts[1]["manager-1"]["url"], "https://server1")
        self.assertEqual((self.root / "manager-ca.pem").read_text(), "CA ONE\n\nCA TWO\n")
        (self.creds / "indexer-password").write_text("line1\nline2")
        self.run_script(CONFIGURE, spec, self.root, self.root / "state", success=False)

    def test_only_declared_indexer_users_and_invalid_hash(self):
        spec = self.root / "users.json"
        spec.write_text(json.dumps([{"name": "admin", "credential": "hash", "backend_roles": ["admin"]}]))
        password_hash = "$2a$12$" + "a" * 53
        (self.creds / "hash").write_text(password_hash + "\n")
        output = self.root / "users.yml"
        self.run_script(USERS, spec, output)
        users = json.loads(output.read_text())
        self.assertEqual(set(users), {"_meta", "admin"})
        self.assertEqual(users["admin"]["hash"], password_hash)
        (self.creds / "hash").write_text("not-a-hash")
        self.run_script(USERS, spec, output, success=False)

    def test_tls_patch_rejects_other_overrides(self):
        directory = self.root / "wazuhCore/server/services"
        directory.mkdir(parents=True)
        client = directory / "server-api-client.js"
        client.write_text("const agent = { rejectUnauthorized: false };")
        self.run_script(PATCH, self.root)
        self.assertIn("rejectUnauthorized: true", client.read_text())
        for override in ['"rejectUnauthorized": false', 'rejectUnauthorized: config.x',
                         'checkServerIdentity: () => undefined']:
            client.write_text("const agent = { rejectUnauthorized: false };")
            (directory / "other.js").write_text("const other = {" + override + "};")
            self.run_script(PATCH, self.root, success=False)

unittest.main()
