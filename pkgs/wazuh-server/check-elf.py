"""Audit interpreter, RPATH and DT_NEEDED of every installed ELF object."""
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
count = 0
for path in root.rglob('*'):
    if not path.is_file() or path.is_symlink():
        continue
    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            continue
    count += 1
    dynamic = subprocess.check_output(['readelf', '-d', str(path)], text=True)
    for line in dynamic.splitlines():
        if any(tag in line for tag in ['(RPATH)', '(RUNPATH)', '(NEEDED)']):
            if any(bad in line for bad in ['/usr/', '/build/', '/tmp/nix-build', 'source/src']):
                raise RuntimeError(f'non-runtime linkage in {path}: {line}')
    headers = subprocess.check_output(['readelf', '-l', str(path)], text=True)
    for line in headers.splitlines():
        if 'Requesting program interpreter:' in line and '/nix/store/' not in line:
            raise RuntimeError(f'non-store interpreter in {path}: {line}')
if count == 0:
    raise RuntimeError('empty ELF scan')
print(f'Checked {count} ELF objects')
