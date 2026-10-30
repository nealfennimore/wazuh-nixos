# Shared by the isolated indexer/dashboard tests and available to stack tests.
{ pkgs, pki, nodeName ? "indexer", defaultListen ? false }:
let
  secrets = pkgs.runCommand "wazuh-indexer-test-users" {
    nativeBuildInputs = [ (pkgs.python3.withPackages (p: [ p.bcrypt ])) ];
  } ''
    mkdir -p $out
    printf '%s' 'Test-password-42!' > $out/password
    printf '%s' admin > $out/admin
    printf '%s' kibanaserver > $out/kibanaserver
    python - <<'PY' > $out/hash
    import bcrypt
    print(bcrypt.hashpw(b'Test-password-42!', bcrypt.gensalt()).decode())
    PY
  '';
  # A second password, Rotated-password-43!, for rotation tests. Kept apart
  # from secrets so that adding it changes no existing derivation.
  rotated = pkgs.runCommand "wazuh-indexer-test-rotated-hash" {
    nativeBuildInputs = [ (pkgs.python3.withPackages (p: [ p.bcrypt ])) ];
  } ''
    mkdir -p $out
    printf '%s' 'Rotated-password-43!' > $out/password
    python - <<'PY' > $out/hash
    import bcrypt
    print(bcrypt.hashpw(b'Rotated-password-43!', bcrypt.gensalt()).decode())
    PY
  '';
in {
  inherit secrets rotated;
  module = {
    imports = [ ../../wazuh-indexer ];
    virtualisation.memorySize = 3072;
    # One vCPU took 176 s to start the JVM on a shared builder.
    virtualisation.cores = 2;
    services.wazuh-indexer = {
      enable = true;
      listenAddress = pkgs.lib.mkIf (!defaultListen) "0.0.0.0";
      openFirewall = true;
      inherit nodeName;
      heapSize = "512m";
      tls = { ca = pki.ca; certificate = pki.${nodeName}.cert; key = pki.${nodeName}.key; };
      nodeDistinguishedNames = [ "CN=${nodeName},O=Wazuh,OU=Wazuh" ];
      admin = {
        certificate = pki.admin.cert;
        key = pki.admin.key;
        distinguishedNames = [ "CN=admin,O=Wazuh,OU=Wazuh" ];
      };
      users = {
        admin = { passwordHashFile = "${secrets}/hash"; backendRoles = [ "admin" ]; };
        kibanaserver.passwordHashFile = "${secrets}/hash";
      };
    };
  };
}
