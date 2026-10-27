{ pkgs, serverPackage ? pkgs.callPackage ./. { } }:
pkgs.runCommand "wazuh-server-package-check" {
  nativeBuildInputs = [ pkgs.stdenv.cc pkgs.python3 pkgs.binutils pkgs.patchelf ];
} ''
  set -euo pipefail
  package=${serverPackage}
  for daemon in analysisd remoted monitord db authd modulesd logcollector syscheckd execd keystore; do
    test -x "$package/bin/wazuh-$daemon"
  done
  test -s "$package/share/wazuh-server/test-support/chroot-source-check"
  test -f "$package/api/scripts/wazuh_apid.py"
  test -s "$package/ruleset/rules/0010-rules_config.xml"
  test -s "$package/share/wazuh-server/ossec-server.conf"

  # A different runtime home from the executable's parent distinguishes an
  # env-first helper from the upstream /proc/self/exe-first implementation.
  cat > probe.cpp <<'CPP'
  #include <iostream>
  #include "homedirHelper.hpp"
  int main() {
    try { std::cout << Utils::findHomeDirectory().string(); }
    catch (const std::exception&) { return 1; }
  }
  CPP
  c++ -std=c++17 -I "$package/share/wazuh-server/test-support" probe.cpp -o home-probe
  # The probe is directly in the working directory, not under bin/.
  test "$(env -u WAZUH_HOME ./home-probe)" = "$PWD"
  mkdir runtime
  runtime="$PWD/runtime"
  test "$(WAZUH_HOME="$runtime" ./home-probe)" = "$runtime"
  if WAZUH_HOME="$runtime/missing" ./home-probe; then
    echo 'C++ helper accepted a nonexistent home' >&2
    exit 1
  fi

  # Match the module's runtime tree. CPython may resolve its prefix into the
  # store; WAZUH_HOME must still govern framework paths, not PYTHONPATH.
  ln -s "$package/framework" "$runtime/framework"
  WAZUH_HOME="$runtime" "$runtime/framework/python/bin/python3" - <<'PY'
  import os
  import wazuh
  import api
  from wazuh.core import common
  assert common.WAZUH_PATH == os.environ['WAZUH_HOME'], common.WAZUH_PATH
  assert common.find_wazuh_path() == os.environ['WAZUH_HOME']
  PY

  # Check runtime ELF linkage, not incidental documentation and CPython test
  # strings. Every ELF must resolve without /usr or transient build RPATHs.
  python3 ${./check-elf.py} "$package"
  mkdir -p "$out"
  printf 'native binaries, C++ home, framework/API imports and ELF linkage checked\n' > "$out/result"
''
