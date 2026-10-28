{ autoPatchelfHook, bzip2, callPackage, fetchFromGitHub, fetchurl, gdbm, lib, libffi,
  libxcrypt, ncurses, python312, readline, sqlite, stdenv, systemd, xz }:
let
  common = import ../common { inherit fetchFromGitHub fetchurl lib; };
  serverDependencies = import ./dependencies.nix {
    inherit fetchurl stdenv;
    inherit (common) dependencyVersion;
  };
  agent = callPackage ../wazuh-agent { };
in
agent.overrideAttrs (old: {
  pname = "wazuh-server";
  dontFixup = false;
  # Runtime wrappers intentionally reference /var/ossec; only build scripts
  # have their shebangs rewritten below.
  dontPatchShebangs = true;
  # logcollector dlopens libsystemd.so.0, so shrink-rpath cannot infer it
  # from DT_NEEDED. autoPatchelf adds this path after the shrink hook.
  runtimeDependencies = [ systemd ];
  nativeBuildInputs = old.nativeBuildInputs ++ [ autoPatchelfHook ];
  buildInputs = old.buildInputs ++ [ bzip2 gdbm libffi libxcrypt ncurses readline sqlite xz ];
  makeFlags = [ "-C src" "TARGET=server" "INSTALLDIR=$(out)" "PYTHON_SOURCE=yes" "CURL=false" ];

  patches = old.patches ++ [
    ./patches/07-cpp-runtime-home.patch
    ./patches/08-python-runtime-home.patch
    # rocksdb builds with -Werror and GCC 15 adds warnings. The <cstdint>
    # include itself comes from the CXX make flag below, for every C++ file.
    ./patches/09-rocksdb-no-werror.patch
  ];
  unpackPhase = old.unpackPhase + ''
    # The agent unpackPhase copies the tree with --no-preserve=all, which
    # drops every execute bit, and it restores only the two scripts its own
    # install path runs. The server Makefile also runs
    # ./analysisd/compiled_rules/register_rule.sh by path. Replay every
    # upstream execute bit instead of naming scripts one at a time, so the
    # build sees the modes a git checkout has. The copy uses "$src"/*, which
    # skips dotfiles such as .gitignore and .github, so only chmod what the
    # copy produced.
    (cd "$src" && find . -type f -perm -u+x -print0) | while IFS= read -r -d "" f; do
      if [ -e "$f" ]; then chmod u+x "$f"; fi
    done
    test -x src/analysisd/compiled_rules/register_rule.sh
    ${lib.concatMapStringsSep "\n" (dep: "tar -xzf ${dep} -C src/external") serverDependencies}
    test -f src/external/cpython/configure
    test -d src/external/cpython/Dependencies/simple
  '';
  # The agent preparation stays identical. Server-only changes are applied
  # after it, without changing the agent's derivation or runtime behavior.
  prePatch = old.prePatch + ''
    ${python312}/bin/python3 ${./prepare-install.py}
    chmod -R u+rwX src/external
    patchShebangs --build src/external
    # The cpython archive carries a Makefile generated on Wazuh's builder:
    # prefix /var/wazuh-manager/framework/python and INSTALL=/usr/bin/install.
    # It also carries a built interpreter, and build_python in src/Makefile
    # skips ./configure when external/cpython/python exists. The first build
    # therefore installed with the foreign prefix and failed on
    # /usr/bin/install. Discard the generated state so build_python runs
    # configure here, with --prefix=$out/framework/python and the
    # sandbox's install.
    if [ -f src/external/cpython/Makefile ]; then
      make -C src/external/cpython distclean
    fi
    rm -f src/external/cpython/python src/external/cpython/Makefile \
      src/external/cpython/config.status src/external/cpython/pyconfig.h
    test ! -e src/external/cpython/python
    test ! -e src/external/cpython/Makefile
    test -x src/external/cpython/configure
  '';
  preBuild = ''
    # GCC 15 no longer includes <cstdint> through other libstdc++ headers. 84
    # first-party headers and the vendored rocksdb use uintN_t without it.
    # A make command-line CXX overrides the Makefile's own CXX=g++, reaches
    # every recipe environment, and CMake splits the trailing argument into
    # CMAKE_CXX_COMPILER_ARG1, so sub-projects that replace CMAKE_CXX_FLAGS
    # keep it. It touches g++ only: clang compiles the BPF object as C.
    # makeFlags is word-split by stdenv; the array keeps the space intact.
    makeFlagsArray+=("CXX=g++ -include cstdint")
    export PIP_INDEX_URL="file://$PWD/src/external/cpython/Dependencies/simple"
    # Keep the local PEP 503 index for nested pip build-isolation processes.
    make -C src TARGET=server PYTHON_SOURCE=yes INSTALLDIR="$out" CURL=false settings
    # All dependencies were extracted from fixed-output inputs. Do not run
    # upstream deps, whose recipes probe network precompiled mirrors.
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"/{bin,etc/shared,queue,var,wodles,logs,lib,tmp,agentless,active-response}
    chmod u+x install.sh src/init/fw-check.sh
    INSTALLDIR="$out" USER_DIR="$out" ./install.sh binary-install
    # install.sh is not fail-fast. Assert its essential results explicitly.
    for daemon in analysisd remoted monitord db authd modulesd logcollector syscheckd execd keystore; do
      test -x "$out/bin/wazuh-$daemon"
    done
    for response in firewall-drop route-null wazuh-slack host-deny disable-account; do
      test -f "$out/active-response/bin/$response"
    done
    chmod u+x "$out"/bin/* "$out"/active-response/bin/*
    rm -f "$out/active-response/bin/restart-wazuh" "$out/active-response/bin/restart.sh"
    rm -rf "$out/src"
    runHook postInstall
  '';
  # CMake records the build tree in the RPATH of every target it links, for
  # example /build/src for libwazuhext. Upstream never installs through
  # CMake, so those entries ride into the package, and the nixpkgs audit
  # rejects them. Every daemon and library already carries $ORIGIN/../lib
  # or $ORIGIN for runtime resolution, and autoPatchelf adds store paths in
  # postFixup, so the build-tree entries are dead weight. Drop them before
  # the fixup hooks run. Relocatable objects such as lib/modern.bpf.o have
  # no RPATH, and patchelf fails on them, so they are skipped.
  preFixup = ''
    find "$out" -type f | while IFS= read -r f; do
      head -c 4 "$f" | grep -q "ELF" || continue
      old=$(patchelf --print-rpath "$f" 2>/dev/null) || continue
      new=$(printf '%s' "$old" | tr ':' '\n' | { grep -v "^$NIX_BUILD_TOP/" || true; } | paste -sd: -)
      if [ "$new" != "$old" ]; then
        echo "dropping build-tree RPATH entries from $f"
        patchelf --set-rpath "$new" "$f"
      fi
    done
  '';
  postInstall = ''
    install -Dm444 etc/ossec-server.conf "$out/share/wazuh-server/ossec-server.conf"
    # CPython's _ctypes links the vendored libffi shared object, soname
    # libffi.so.6, from external/libffi/server/.libs. Upstream relies on the
    # build host to provide that soname at runtime. nixpkgs libffi is .so.8,
    # so autoPatchelf cannot satisfy it. Ship the vendored library next to
    # the other Wazuh libraries, where autoPatchelf and $ORIGIN find it.
    cp -a src/external/libffi/server/.libs/libffi.so.[0-9]* "$out/lib/"
    test -f "$out/lib/libffi.so.6"
    # Keep the patched helper available to the executable package check.
    # installPhase removes src, so the source guard/probe is staged preInstall.
    chmod -R u+rwX,go+rX "$out"
    rm -f "$out/etc/sslmanager.key" "$out/etc/sslmanager.cert"
    test -x "$out/framework/python/bin/python3"
    test -f "$out/api/scripts/wazuh_apid.py"
  '';
  preInstall = ''
    mkdir -p "$out/share/wazuh-server/test-support"
    cp src/shared_modules/utils/homedirHelper.hpp "$out/share/wazuh-server/test-support/"
    ${python312}/bin/python3 ${./check-chroot-source.py} . > "$out/share/wazuh-server/test-support/chroot-source-check"
    # upstream install.sh calls make wpython and framework/api installs.
    export PIP_INDEX_URL="file://$PWD/src/external/cpython/Dependencies/simple"
    export PIP_CONFIG_FILE=/dev/null
    export PIP_EXTRA_INDEX_URL=""
    unset PIP_NO_INDEX PIP_FIND_LINKS
    export PIP_DISABLE_PIP_VERSION_CHECK=1
  '';
  meta = old.meta // { description = "Wazuh server (manager and API)"; };
})
