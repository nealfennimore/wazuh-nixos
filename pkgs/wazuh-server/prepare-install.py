"""Adapt only build/install code; runtime identity belongs to systemd."""
from pathlib import Path
import re


def replace_once(path, before, after):
    data = path.read_text()
    if data.count(before) != 1:
        raise RuntimeError(f"upstream anchor changed: {path}: {before!r}")
    path.write_text(data.replace(before, after))


replace_once(Path('install.sh'), 'if [ ! "X$ME" = "Xroot" ]; then', 'if false; then')
replace_once(Path('etc/preloaded-vars.conf'), 'USER_INSTALL_TYPE="agent"', 'USER_INSTALL_TYPE="server"')
# TLS material must be supplied at runtime, never generated in a derivation.
replace_once(Path('src/init/inst-functions.sh'), '\n    GenerateAuthCert\n', '\n    # Runtime TLS is supplied by the NixOS module.\n')
for name in ['src/init/inst-functions.sh', 'src/Makefile', 'framework/Makefile', 'api/Makefile']:
    path = Path(name)
    data = path.read_text()
    # install's ownership flags cannot work in an unprivileged Nix builder.
    # Preserve all install modes; normal fixup makes the store tree readable.
    data = re.sub(r' -[og] (?:root|0|\$\{WAZUH_(?:USER|GROUP)\})\b', '', data)
    # The closing brace is not a word character, so handle those separately.
    data = re.sub(r' -[og] \$\{WAZUH_(?:USER|GROUP)\}', '', data)
    data = re.sub(r'(?m)^([ \t]*)chown [^\n]*$', r'\1: # Ownership assigned at activation.', data)
    path.write_text(data)
# Keep pip offline even for isolated framework/API build environments.
# install_framework/api run sequentially in the install phase.
replace_once(Path('src/Makefile'), 'wpython: install_dependencies install_framework install_api install_mitre',
             '.NOTPARALLEL: wpython\nwpython: install_dependencies install_framework install_api install_mitre')
