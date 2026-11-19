# Load the ruleset at build time, as wazuh-analysisd does at its start.
#
# The derivation builds a manager home from the package, puts the declared
# files and the generated ossec.conf in it, and runs `wazuh-analysisd -t`.
# That mode chroots to the home before it reads the ruleset
# (src/analysisd/analysisd.c, Privsep_Chroot before ReadDecodeXML) and looks
# up the wazuh user first. A build has neither the capability nor the user,
# so two preloaded libraries supply them: fakechroot turns the chroot into a
# path prefix, and nss_wrapper answers the lookup from two files.
#
# The host directories etc/rules, etc/decoders and etc/lists hold the
# package defaults here. A file that the API uploaded on a host is not part
# of this check.
#
# A warning fails the check too. analysisd only warns when a rule names a
# list that does not load, and then ignores the rule. The stock ruleset
# loads without a warning, so each warning comes from a declared file.
{
  pkgs,
  package,
  ossecConf,
  tree,
}:
pkgs.runCommand "wazuh-server-ruleset-check" { } ''
  home=$PWD/home
  mkdir -p "$home"
  cp -R ${package}/ruleset "$home/ruleset"
  cp -R ${package}/etc "$home/etc"
  chmod -R u+w "$home"
  mkdir -p "$home/etc/declared" "$home/logs" "$home/queue/sockets" "$home/var/run" "$home/tmp" "$home/stats"
  cp -RL ${tree}/. "$home/etc/declared/"
  chmod -R u+w "$home"
  cp ${ossecConf} "$home/etc/ossec.conf"

  echo "wazuh:x:$(id -u):$(id -g):wazuh:$home:/bin/sh" > passwd
  echo "wazuh:x:$(id -g):" > group

  status=0
  WAZUH_HOME=$home \
    NSS_WRAPPER_PASSWD=$PWD/passwd NSS_WRAPPER_GROUP=$PWD/group \
    LD_PRELOAD="${pkgs.fakechroot}/lib/fakechroot/libfakechroot.so ${pkgs.nss_wrapper}/lib/libnss_wrapper.so" \
    ${package}/bin/wazuh-analysisd -t > output 2>&1 || status=$?

  if [ "$status" != 0 ] || grep -E 'wazuh-analysisd: (WARNING|ERROR|CRITICAL):' output; then
    echo "services.wazuh-server.ruleset: wazuh-analysisd does not accept the declared ruleset (exit $status):" >&2
    sort -u output | grep -v ': INFO: ' >&2 || true
    exit 1
  fi
  touch "$out"
''
