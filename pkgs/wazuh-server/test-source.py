"""Source boundary tests runnable without Nix or server dependency downloads.

Usage: python3 pkgs/wazuh-server/test-source.py /path/to/pinned/wazuh/source
These complement, and cannot replace, package-check.nix and the VM tests.
"""
import ast
from functools import lru_cache
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(sys.argv.pop(1)).resolve()
HERE = Path(__file__).resolve().parent


class SourceBoundaries(unittest.TestCase):
    def test_framework_runtime_home(self):
        tree = ast.parse((SOURCE / 'framework/wazuh/core/common.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'find_wazuh_path')
        namespace = {'os': os, 'lru_cache': lru_cache,
                     '__file__': '/nix/store/test-server/framework/python/lib/python3.10/site-packages/wazuh/core/common.py'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'common.py', 'exec'), namespace)
        find = namespace['find_wazuh_path']
        with tempfile.TemporaryDirectory() as runtime, patch.dict(os.environ, {'WAZUH_HOME': runtime}):
            self.assertEqual(find(), runtime)
        find.cache_clear()
        with patch.dict(os.environ, {'WAZUH_HOME': '/nonexistent-wazuh-runtime-path'}):
            with self.assertRaises(ValueError):
                find()
        find.cache_clear()
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(find(), '/nix/store/test-server')

    def test_chroot_guard_detects_each_removed_call(self):
        names = ['analysisd/analysisd.c', 'remoted/main.c', 'monitord/main.c', 'wazuh_db/main.c']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                target = root / 'src' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE / 'src' / name, target)
            result = subprocess.run([sys.executable, str(HERE / 'check-chroot-source.py'), str(root)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for name in names:
                target = root / 'src' / name
                original = target.read_text()
                self.assertIn('Privsep_Chroot(home_path)', original)
                target.write_text(original.replace('Privsep_Chroot(home_path)', 'disabled_chroot(home_path)'))
                result = subprocess.run([sys.executable, str(HERE / 'check-chroot-source.py'), str(root)], capture_output=True)
                self.assertNotEqual(result.returncode, 0, name)
                target.write_text(original)

    def test_unprivileged_install_preparation(self):
        names = ['install.sh', 'src/init/inst-functions.sh', 'src/Makefile', 'framework/Makefile', 'api/Makefile', 'tools/mitre/mitredb.py']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE / name, target)
            (root / 'etc').mkdir()
            (root / 'etc/preloaded-vars.conf').write_text('USER_INSTALL_TYPE="agent"\n')
            result = subprocess.run([sys.executable, str(HERE / 'prepare-install.py')], cwd=root, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn('USER_INSTALL_TYPE="server"', (root / 'etc/preloaded-vars.conf').read_text())
            self.assertNotIn('\n    GenerateAuthCert\n', (root / 'src/init/inst-functions.sh').read_text())
            for name in names[1:]:
                data = (root / name).read_text()
                self.assertNotRegex(data, r' -[og] (?:root|0|\$\{WAZUH_(?:USER|GROUP)\})')
            self.assertIn('.NOTPARALLEL: wpython', (root / 'src/Makefile').read_text())
            makefile = (root / 'src/Makefile').read_text()
            # The CPython configure line must carry the Nix include and library
            # paths inside the quoted CPPFLAGS and LDFLAGS arguments.
            self.assertIn('include ${CPYTHON_NIX_CPPFLAGS}" LIBS="-lwazuhext"', makefile)
            self.assertIn('--disable-new-dtags ${CPYTHON_NIX_LDFLAGS}" CPPFLAGS="', makefile)
            self.assertIn('wpython INSTALLDIR=${INSTALLDIR} TARGET=${INSTYPE} || exit 1\n',
                          (root / 'src/init/inst-functions.sh').read_text())
            # Run the patched entry point with runtime identity operations forbidden.
            tree = ast.parse((root / 'tools/mitre/mitredb.py').read_text())
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'main')
            database = root / 'mitre.db'
            def populate(pathfile, session, destination):
                Path(destination).write_bytes(b'MITRE test data')
            parse_json = Mock(side_effect=populate)
            namespace = {'os': os, 'find': Mock(return_value='enterprise-attack.json'),
                         'create_engine': Mock(), 'sessionmaker': Mock(),
                         'Base': Mock(), 'parse_json': parse_json,
                         'pwd': Mock(), 'grp': Mock()}
            namespace['pwd'].getpwnam.side_effect = AssertionError('build user lookup')
            namespace['grp'].getgrnam.side_effect = KeyError('wazuh')
            exec(compile(ast.Module(body=[main], type_ignores=[]), 'mitredb.py', 'exec'), namespace)
            with patch.object(os, 'chown', side_effect=AssertionError('build chown')):
                namespace['main'](str(database))
            parse_json.assert_called_once()
            self.assertEqual(database.read_bytes(), b'MITRE test data')
            self.assertEqual(database.stat().st_mode & 0o777, 0o660)
            for name in ['install.sh', 'src/init/inst-functions.sh']:
                result = subprocess.run(['bash', '-n', str(root / name)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())


unittest.main()
