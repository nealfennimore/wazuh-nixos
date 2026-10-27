#!/usr/bin/env bash
# Writes a separate server manifest without changing the agent's input set.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
# Read the single shared dependency pin; fail if its format changes.
dependency_version="$(sed -n 's/^  dependencyVersion = "\([0-9][0-9]*\)";$/\1/p' "$script_dir/../common/default.nix")"
if [[ ! "$dependency_version" =~ ^[0-9]+$ ]]; then
  echo "Cannot read dependencyVersion from pkgs/common/default.nix" >&2
  exit 1
fi
base_url="${BASE_URL:-https://packages.wazuh.com/deps/${dependency_version}/libraries/sources}"
manifest="$work_dir/dependency-hashes.json"
printf '{\n' > "$manifest"
separator=''
for name in cpython_x86_64 cpython_arm64 jemalloc flatbuffers simdjson; do
  curl --fail --location --retry 2 "$base_url/$name.tar.gz" -o "$work_dir/$name.tar.gz"
  gzip -t "$work_dir/$name.tar.gz"
  # Check archive roots as well as compression, especially the per-arch cpython.
  expected="$name"
  case "$name" in cpython_*) expected=cpython ;; esac
  tar -tzf "$work_dir/$name.tar.gz" > "$work_dir/contents"
  if ! awk -v root="$expected" 'BEGIN { found=0 } { sub(/^\.\//, ""); if ($0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/) exit 1; if ($0 == root || index($0, root "/") == 1) found=1; else exit 1 } END { if (!found) exit 1 }' "$work_dir/contents"; then
    echo "Unexpected archive root for $name (expected $expected)" >&2
    exit 1
  fi
  sri="$(openssl dgst -sha256 -binary "$work_dir/$name.tar.gz" | base64 | tr -d '\n')"
  printf '%s  "%s": "sha256-%s"' "$separator" "$name" "$sri" >> "$manifest"
  separator=$',\n'
done
printf '\n}\n' >> "$manifest"
mv -- "$manifest" "$script_dir/dependency-hashes.json"
echo "Wrote $script_dir/dependency-hashes.json" >&2
