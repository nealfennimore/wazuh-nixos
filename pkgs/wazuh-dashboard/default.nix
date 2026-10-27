{ lib, stdenv, fetchurl, dpkg, autoPatchelfHook, makeWrapper, python3, zlib, openssl, coreutils, findutils, gnugrep }:
let
  pin = builtins.fromJSON (builtins.readFile ./source.json);
  arch = { x86_64-linux = "amd64"; aarch64-linux = "arm64"; }.${stdenv.hostPlatform.system};
in stdenv.mkDerivation {
  pname = "wazuh-dashboard";
  inherit (pin) version;
  src = fetchurl {
    url = "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-dashboard/wazuh-dashboard_${pin.version}-${pin.revision}_${arch}.deb";
    hash = pin.hashes.${arch} or (throw "Run pkgs/wazuh-indexer/prefetch.sh and commit the release hashes before building Wazuh indexer/dashboard.");
  };
  nativeBuildInputs = [ dpkg autoPatchelfHook makeWrapper python3 ];
  buildInputs = [ stdenv.cc.cc.lib zlib openssl ];
  unpackPhase = "dpkg-deb -x $src unpacked";
  dontBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/wazuh-dashboard $out/bin
    cp -a unpacked/usr/share/wazuh-dashboard/. $out/share/wazuh-dashboard/
    rm -rf $out/share/wazuh-dashboard/config
    cp -a unpacked/etc/wazuh-dashboard $out/share/wazuh-dashboard/config
    # Patch the compiled upstream client; abort if its layout/code changes.
    python3 ${./verify-manager-tls.py} $out/share/wazuh-dashboard/plugins
    patchShebangs $out/share/wazuh-dashboard/bin
    makeWrapper $out/share/wazuh-dashboard/bin/opensearch-dashboards $out/bin/wazuh-dashboard \
      --set-default OSD_PATH_CONF /run/wazuh-dashboard \
      --prefix PATH : ${lib.makeBinPath [ coreutils findutils gnugrep ]}
    runHook postInstall
  '';
  meta = {
    description = "Wazuh dashboard with upstream plugins and verified manager TLS";
    homepage = "https://github.com/wazuh/wazuh-dashboard";
    license = [ lib.licenses.asl20 lib.licenses.gpl2Plus ];
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "wazuh-dashboard";
  };
}
