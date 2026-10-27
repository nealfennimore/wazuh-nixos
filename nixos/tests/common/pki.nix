# A throwaway PKI for the NixOS tests. Every component test and the stack test
# imports it, so all nodes trust one CA.
#
#   pki = import ./common/pki.nix { inherit pkgs; };
#   pki.ca            # CA certificate
#   pki.wrongCa       # an unrelated CA, for wrong-CA rejection tests
#   pki.<node>.cert   # node certificate, SAN = DNS:<node>
#   pki.<node>.key    # node key, PKCS#8 (the indexer rejects PKCS#1)
#
# Nodes: server, indexer, dashboard, agent, plus "admin". The indexer's
# securityadmin tool authenticates with the admin certificate.
#
# Do not use these keys outside tests. They are in the world-readable store.
{
  pkgs,
  nodes ? [
    "server"
    "indexer"
    "dashboard"
    "agent"
    "admin"
  ],
}:
let
  inherit (pkgs) lib;

  out = pkgs.runCommand "wazuh-test-pki" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    cd $out

    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/OU=Wazuh/O=Wazuh/CN=wazuh-test-ca" \
      -keyout ca.key -out ca.pem

    # An unrelated CA. A client that trusts only this CA must reject every node
    # certificate. Tests use it to prove that verification is on.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/OU=Wazuh/O=Wazuh/CN=wazuh-test-wrong-ca" \
      -keyout wrong-ca.key -out wrong-ca.pem
    rm wrong-ca.key

    ${lib.concatMapStrings (node: ''
      openssl req -newkey rsa:2048 -nodes \
        -subj "/OU=Wazuh/O=Wazuh/CN=${node}" \
        -keyout ${node}.rsa.key -out ${node}.csr
      printf 'subjectAltName=DNS:${node}\nextendedKeyUsage=serverAuth,clientAuth\n' > ${node}.ext
      openssl x509 -req -in ${node}.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 3650 -extfile ${node}.ext -out ${node}.pem
      openssl pkcs8 -topk8 -nocrypt -in ${node}.rsa.key -out ${node}.key
      openssl verify -CAfile ca.pem ${node}.pem
      rm ${node}.rsa.key ${node}.csr ${node}.ext
    '') nodes}
  '';
in
{
  ca = "${out}/ca.pem";
  wrongCa = "${out}/wrong-ca.pem";
  drv = out;
}
// lib.genAttrs nodes (node: {
  cert = "${out}/${node}.pem";
  key = "${out}/${node}.key";
})
