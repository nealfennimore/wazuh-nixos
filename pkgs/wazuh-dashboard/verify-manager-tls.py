"""Patch the Wazuh API client, refusing unknown release layouts."""
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
clients = list(root.glob("**/server/services/server-api-client.js"))
if len(clients) != 1:
    raise SystemExit(f"Expected one compiled Wazuh API client; found {len(clients)}")
client = clients[0]
source = client.read_text()
patched, count = re.subn(r"rejectUnauthorized\s*:\s*false\b", "rejectUnauthorized: true", source)
if count != 1:
    raise SystemExit(f"Expected one insecure HTTPS agent; found {count}")
client.write_text(patched)
