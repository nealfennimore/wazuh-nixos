"""Adapt only build/install code; runtime identity belongs to systemd."""
from pathlib import Path
import re


def replace_once(path, before, after):
    data = path.read_text()
    if data.count(before) != 1:
        raise RuntimeError(f"upstream anchor changed: {path}: {before!r}")
    path.write_text(data.replace(before, after))


replace_once(Path('install.sh'), 'if [ ! "X$ME" = "Xroot" ]; then', 'if false; then')
replace_once(Path('etc/preloaded-vars.conf'), 'USER_INSTALL_TYPE="agent"', 'USER_INSTALL_TYPE="server"')
# build_python passes CPPFLAGS and LDFLAGS as configure arguments, which
# override the environment. CPython's setup.py finds optional modules such
# as zlib only through the -I and -L entries configure recorded, and a Nix
# sandbox has no /usr/include. Append the store paths from the derivation.
replace_once(Path('src/Makefile'), 'include" LIBS="-lwazuhext"',
             'include ${CPYTHON_NIX_CPPFLAGS}" LIBS="-lwazuhext"')
replace_once(Path('src/Makefile'), '--disable-new-dtags" CPPFLAGS="',
             '--disable-new-dtags ${CPYTHON_NIX_LDFLAGS}" CPPFLAGS="')
# TLS material must be supplied at runtime, never generated in a derivation.
replace_once(Path('src/init/inst-functions.sh'), '\n    GenerateAuthCert\n', '\n    # Runtime TLS is supplied by the NixOS module.\n')
# InstallServer creates templates/ with mode 0440 and then installs the index
# templates into it. Root ignores the missing search bit. The unprivileged
# builder does not, so every install into it failed silently. wazuh-modulesd
# opens these files when vulnerability detection or the inventory harvester
# starts with an indexer.
replace_once(Path('src/init/inst-functions.sh'),
             '${INSTALL} -d -m 0440 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/templates\n',
             '${INSTALL} -d -m 0750 -o root -g ${WAZUH_GROUP} ${INSTALLDIR}/templates\n')
# install.sh is not fail-fast. make wpython installs the interpreter, the pip
# requirements and the wazuh and api packages. A failed step must stop the
# build with its error at the end of the log, not leave a tree without them.
replace_once(Path('src/init/inst-functions.sh'),
             '    ${MAKEBIN} wpython INSTALLDIR=${INSTALLDIR} TARGET=${INSTYPE}\n',
             '    ${MAKEBIN} wpython INSTALLDIR=${INSTALLDIR} TARGET=${INSTYPE} || exit 1\n')
for name in ['src/init/inst-functions.sh', 'src/Makefile', 'framework/Makefile', 'api/Makefile']:
    path = Path(name)
    data = path.read_text()
    # install's ownership flags cannot work in an unprivileged Nix builder.
    # Preserve all install modes; normal fixup makes the store tree readable.
    data = re.sub(r' -[og] (?:root|0|\$\{WAZUH_(?:USER|GROUP)\})\b', '', data)
    # The closing brace is not a word character, so handle those separately.
    data = re.sub(r' -[og] \$\{WAZUH_(?:USER|GROUP)\}', '', data)
    data = re.sub(r'(?m)^([ \t]*)chown [^\n]*$', r'\1: # Ownership assigned at activation.', data)
    path.write_text(data)
# Keep pip offline even for isolated framework/API build environments.
# install_framework/api run sequentially in the install phase.
replace_once(Path('src/Makefile'), 'wpython: install_dependencies install_framework install_api install_mitre',
             '.NOTPARALLEL: wpython\nwpython: install_dependencies install_framework install_api install_mitre')
# The build sandbox has no runtime wazuh group and cannot chown to root.
# Keep database generation and its mode; activation owns runtime identity.
replace_once(Path('tools/mitre/mitredb.py'),
             '    uid = pwd.getpwnam("root").pw_uid\n'
             '    gid = grp.getgrnam("wazuh").gr_gid\n'
             '    os.chown(database, uid, gid)\n',
             '    # Ownership assigned at activation.\n')
