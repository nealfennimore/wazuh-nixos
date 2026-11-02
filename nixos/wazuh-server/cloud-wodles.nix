# Keep Python code immutable and move cloud collector databases to var/.
{ pkgs, package }:
pkgs.runCommand "wazuh-server-cloud-wodles"
  {
    nativeBuildInputs = [ pkgs.python3 ];
  }
  ''
    cp -R --no-preserve=ownership,mode ${package}/wodles "$out"
    chmod -R u+w "$out"
    python3 - "$out" <<'PY'
    import pathlib
    import sys
    root = pathlib.Path(sys.argv[1])
    changes = {
        "aws/wazuh_integration.py": (
            'self.wazuh_wodle = path.join(self.wazuh_path, "wodles", "aws")',
            'self.wazuh_wodle = path.join(self.wazuh_path, "var", "wodles", "aws")',
        ),
        "gcloud/buckets/bucket.py": (
            'join(utils.find_wazuh_path(), "wodles/gcloud/gcloud.db")',
            'join(utils.find_wazuh_path(), "var/wodles/gcloud/gcloud.db")',
        ),
        "azure/db/orm.py": (
            'MODULE_ROOT_DIR = dirname(dirname(abspath(__file__)))',
            'MODULE_ROOT_DIR = join(dirname(dirname(dirname(dirname(abspath(__file__))))), "var", "wodles", "azure")',
        ),
    }
    for name, (old, new) in changes.items():
        path = root / name
        text = path.read_text()
        if text.count(old) != 1:
            raise RuntimeError(f"{name}: expected exactly one database-path anchor")
        path.write_text(text.replace(old, new))
    PY
  ''
