"""Render JSON (valid YAML) without placing password hashes in the store."""
import json
import os
import pathlib
import re
import sys

users = {"_meta": {"type": "internalusers", "config_version": 2}}
credentials = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])
for user in json.loads(pathlib.Path(sys.argv[1]).read_text()):
    password_hash = (credentials / user["credential"]).read_text().rstrip("\r\n")
    if not re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", password_hash):
        raise SystemExit("Invalid bcrypt credential for indexer user")
    users[user["name"]] = {"hash": password_hash, "reserved": True,
                           "backend_roles": user["backend_roles"]}
pathlib.Path(sys.argv[2]).write_text(json.dumps(users))
