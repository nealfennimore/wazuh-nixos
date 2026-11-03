"""Refuse silently omitted or duplicated flake checks in the CI manifests."""
import collections
import json
import pathlib
import sys

available = set(json.loads(pathlib.Path(sys.argv[1]).read_text()))
manifests = [pathlib.Path('.github/non-vm-checks.txt')]
manifests += sorted(pathlib.Path('.github/vm-checks').glob('*.txt'))
checks = [line.strip() for path in manifests for line in path.read_text().splitlines() if line.strip()]
# The upstream suite has a 12-hour limit; hosted Actions jobs stop at six hours.
excluded = {'integration'}
duplicates = [name for name, count in collections.Counter(checks).items() if count > 1]
missing = available - set(checks) - excluded
unknown = set(checks) - available
if duplicates or missing or unknown or excluded & set(checks):
    raise SystemExit(f'CI check coverage mismatch: duplicates={duplicates}, missing={sorted(missing)}, unknown={sorted(unknown)}, excluded_included={sorted(excluded & set(checks))}')
print(f'CI covers {len(checks)} of {len(available)} checks; excluded: {sorted(excluded)}')
