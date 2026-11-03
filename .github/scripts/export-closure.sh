#!/usr/bin/env bash
set -euo pipefail
archive=$1
shift
paths_file=$(mktemp)
trap 'rm -f "$paths_file"' EXIT
nix path-info --recursive "$@" > "$paths_file"
mapfile -t paths < "$paths_file"
nix-store --export "${paths[@]}" | zstd -T2 -3 -o "$archive"
