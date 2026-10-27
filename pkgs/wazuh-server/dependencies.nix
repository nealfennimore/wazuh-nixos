{ fetchurl, stdenv, dependencyVersion }:
let
  manifestPath = ./dependency-hashes.json;
  hashes = if builtins.pathExists manifestPath then builtins.fromJSON (builtins.readFile manifestPath)
    else throw "Wazuh server dependency hashes missing: run pkgs/wazuh-server/prefetch-dependencies.sh on a host with packages.wazuh.com access";
  arch = if stdenv.hostPlatform.isx86_64 then "x86_64"
    else if stdenv.hostPlatform.isAarch64 then "arm64"
    else throw "Wazuh server supports x86_64-linux and aarch64-linux";
  names = [ "cpython_${arch}" "jemalloc" "flatbuffers" "simdjson" ];
in
map (name: fetchurl {
  url = "https://packages.wazuh.com/deps/${dependencyVersion}/libraries/sources/${name}.tar.gz";
  hash = hashes.${name};
}) names
