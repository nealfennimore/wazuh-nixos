#!/usr/bin/env bash
# Run on a host with access to packages.wazuh.com. Updates both manifests only
# after all downloads succeed. No Nix installation is needed for flat hashes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for component in indexer dashboard; do
  manifest="$root/wazuh-$component/source.json"
  version=$(jq -er .version "$manifest")
  revision=$(jq -er .revision "$manifest")
  cp "$manifest" "$work/$component.json"
  for arch in amd64 arm64; do
    url="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-$component/wazuh-${component}_${version}-${revision}_${arch}.deb"
    curl --fail --location --retry 2 "$url" -o "$work/package.deb"
    hash="sha256-$(openssl dgst -sha256 -binary "$work/package.deb" | openssl base64 -A)"
    jq --arg arch "$arch" --arg hash "$hash" '.hashes[$arch] = $hash' \
      "$work/$component.json" > "$work/next.json"
    mv "$work/next.json" "$work/$component.json"
  done
done
for component in indexer dashboard; do
  mv "$work/$component.json" "$root/wazuh-$component/source.json"
done
