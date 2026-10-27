"""Render YAML-compatible JSON from systemd credentials, never shell strings."""
import json
import os
import pathlib
import sys
from urllib.parse import urlsplit

spec = json.loads(pathlib.Path(sys.argv[1]).read_text())
runtime, state = map(pathlib.Path, sys.argv[2:4])
credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])


def read(name):
    value = (credentials / name).read_text().rstrip("\r\n")
    if not value or "\n" in value or "\r" in value or "\0" in value:
        raise SystemExit(f"Invalid single-line credential: {name}")
    return value


settings = spec["settings"]
settings["opensearch.username"] = read("indexer-username")
settings["opensearch.password"] = read("indexer-password")
hosts, authorities = [], []
for manager in spec["managers"]:
    name = manager["id"]
    url = urlsplit(manager["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.port or url.path or url.query or url.fragment:
        raise SystemExit("Manager URL must be an HTTPS origin with port specified separately")
    hosts.append({name: {"url": manager["url"], "port": manager["port"],
                         "username": read(f"{name}-username"),
                         "password": read(f"{name}-password"),
                         "run_as": manager["runAs"]}})
    ca = credentials / f"{name}-ca"
    if ca.exists():
        authorities.append(ca.read_text())
(runtime / "opensearch_dashboards.yml").write_text(json.dumps(settings))
(runtime / "manager-ca.pem").write_text("\n".join(authorities))
config_dir = state / "wazuh/config"
config_dir.mkdir(parents=True, exist_ok=True)
(config_dir / "wazuh.yml").write_text(json.dumps({"hosts": hosts}))
