# Fast credential and TLS-patch tests; no release package is imported.
{ pkgs }:
pkgs.runCommand "wazuh-dashboard-rendering" { nativeBuildInputs = [ pkgs.python3 ]; } ''
  python ${./rendering.py} \
    ${../../wazuh-dashboard/configure.py} \
    ${../../wazuh-indexer/users.py} \
    ${../../../pkgs/wazuh-dashboard/verify-manager-tls.py}
  touch $out
''
