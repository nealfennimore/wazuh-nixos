{ lib, stdenv, fetchurl, dpkg, autoPatchelfHook, makeWrapper, zlib, openssl, jdk21_headless, bash, coreutils, gnugrep, gnused, util-linux }:
let
  pin = builtins.fromJSON (builtins.readFile ./source.json);
  arch = { x86_64-linux = "amd64"; aarch64-linux = "arm64"; }.${stdenv.hostPlatform.system};
in stdenv.mkDerivation {
  pname = "wazuh-indexer";
  inherit (pin) version;
  src = fetchurl {
    url = "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_${pin.version}-${pin.revision}_${arch}.deb";
    hash = pin.hashes.${arch} or (throw "Run pkgs/wazuh-indexer/prefetch.sh and commit the release hashes before building Wazuh indexer/dashboard.");
  };
  nativeBuildInputs = [ dpkg autoPatchelfHook makeWrapper ];
  buildInputs = [ stdenv.cc.cc.lib zlib openssl ];
  unpackPhase = "dpkg-deb -x $src unpacked";
  dontBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/wazuh-indexer $out/bin
    cp -a unpacked/usr/share/wazuh-indexer/. $out/share/wazuh-indexer/
    rm -rf $out/share/wazuh-indexer/jdk
    rm -rf $out/share/wazuh-indexer/config
    cp -a unpacked/etc/wazuh-indexer $out/share/wazuh-indexer/config
    # Never inherit the distribution's demo password database.
    rm $out/share/wazuh-indexer/config/opensearch-security/internal_users.yml
    patchShebangs $out/share/wazuh-indexer/bin $out/share/wazuh-indexer/plugins
    makeWrapper $out/share/wazuh-indexer/bin/opensearch $out/bin/wazuh-indexer \
      --set OPENSEARCH_HOME $out/share/wazuh-indexer \
      --set OPENSEARCH_JAVA_HOME ${jdk21_headless} \
      --set-default OPENSEARCH_PATH_CONF /run/wazuh-indexer \
      --prefix PATH : ${lib.makeBinPath [ bash coreutils gnugrep gnused util-linux ]}
    makeWrapper $out/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      $out/bin/wazuh-indexer-securityadmin \
      --set JAVA_HOME ${jdk21_headless} \
      --prefix PATH : ${lib.makeBinPath [ bash coreutils gnugrep gnused ]}
    runHook postInstall
  '';
  meta = {
    description = "Wazuh indexer with upstream plugins and a headless Java 21 runtime";
    homepage = "https://github.com/wazuh/wazuh-indexer";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "wazuh-indexer";
  };
}
