# filebeat OSS 7.10.2, the shipper the upstream Wazuh server installs
# (wazuh-docker build-docker-images/wazuh-manager/Dockerfile at v4.14.8:
# FILEBEAT_CHANNEL=filebeat-oss, FILEBEAT_VERSION=7.10.2, installed with yum
# from the Wazuh package repository).
#
# Why not nixpkgs filebeat7. Since 7.13, libbeat calls GET /_license on
# every connection to the output and refuses a cluster that does not answer
# it ("could not connect to a compatible version of Elasticsearch"). The
# Wazuh indexer is OpenSearch and has no /_license route. checks.server-indexer
# showed exactly that with 7.17.27. 7.10.2 predates the check.
#
# Source. Wazuh mirrors the rpm in its yum repository, the one Wazuh host
# the builder reaches. artifacts.elastic.co is not reachable from it. The
# rpm is unpacked, not installed: the binary, the shipped module tree and
# fields.yml are copied, the systemd unit and the default configuration are
# left behind. The NixOS module supplies its own configuration and the
# Wazuh module.
#
# Systems. The Wazuh repository carries the x86_64 rpm only (the aarch64
# name answers 403). On any other system this evaluates to a derivation
# that fails at build time with that message, so that `nix flake check`
# still evaluates the flake for every supported system. The aarch64 build
# is at artifacts.elastic.co/downloads/beats/filebeat/
# filebeat-oss-7.10.2-linux-arm64.tar.gz, which the builder cannot reach.
{
  lib,
  stdenv,
  fetchurl,
  runCommand,
  rpmextract,
  autoPatchelfHook,
}:
let
  version = "7.10.2";
  sources = {
    x86_64-linux = {
      arch = "x86_64";
      hash = "sha256-VoIFMN10nWG6J1Ds78OQOTqKUCndQxvy6valmahH+PI=";
    };
  };
  source = sources.${stdenv.hostPlatform.system} or null;
in
if source == null then
  runCommand "filebeat-oss-${version}-unsupported" { } ''
    echo "filebeat-oss: no verified source for ${stdenv.hostPlatform.system}." >&2
    echo "See pkgs/filebeat-oss/default.nix for the upstream URL." >&2
    exit 1
  ''
else
stdenv.mkDerivation {
  pname = "filebeat-oss";
  inherit version;

  src = fetchurl {
    url = "https://packages.wazuh.com/4.x/yum/filebeat-oss-${version}-${source.arch}.rpm";
    inherit (source) hash;
  };

  nativeBuildInputs = [
    rpmextract
    autoPatchelfHook
  ];

  unpackPhase = ''
    runHook preUnpack
    rpmextract "$src"
    test -x usr/share/filebeat/bin/filebeat
    runHook postUnpack
  '';

  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 usr/share/filebeat/bin/filebeat $out/bin/filebeat
    install -d $out/share/filebeat
    cp -R usr/share/filebeat/module $out/share/filebeat/
    install -m444 etc/filebeat/fields.yml $out/share/filebeat/fields.yml
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    $out/bin/filebeat version | grep -q 'filebeat version ${version}'
    runHook postInstallCheck
  '';

  meta = {
    description = "Lightweight shipper for log files, Apache licensed build";
    homepage = "https://www.elastic.co/beats/filebeat";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    mainProgram = "filebeat";
  };
}
