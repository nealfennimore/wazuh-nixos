# Shared by the isolated indexer/dashboard tests and available to stack tests.
{ pkgs, pki }:
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
in {
  inherit secrets;
  module = {
    imports = [ ../../wazuh-indexer ];
    virtualisation.memorySize = 3072;
    services.wazuh-indexer = {
      enable = true;
      listenAddress = "0.0.0.0";
      openFirewall = true;
      nodeName = "indexer";
      heapSize = "512m";
      tls = { ca = pki.ca; certificate = pki.indexer.cert; key = pki.indexer.key; };
      nodeDistinguishedNames = [ "CN=indexer,O=Wazuh,OU=Wazuh" ];
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
