"""Fail a server build if a downstream patch disables upstream chroot."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
for name in ['analysisd/analysisd.c', 'remoted/main.c', 'monitord/main.c', 'wazuh_db/main.c']:
    path = root / 'src' / name
    text = path.read_text()
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    if not re.search(r'\bPrivsep_Chroot\s*\(\s*home_path\s*\)', text):
        raise RuntimeError(f'upstream chroot call missing from {path}')
print('All four server daemons retain Privsep_Chroot(home_path)')
