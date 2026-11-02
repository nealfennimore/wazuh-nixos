# Runs a packaged integration script with its secrets.
#
#   python3 integration-secrets.py <secrets dir> <script> <integratord arguments>
#
# integratord puts <api_key> and <hook_url> on the command line of the
# integration (src/os_integrator/integrator.c, exec_full_cmd). The module
# writes a token @WAZUH_SECRET_<id>@ there instead, and this program replaces
# each token in sys.argv with the content of <secrets dir>/<id>. A change to
# sys.argv does not change /proc/<pid>/cmdline, so the secret is never a
# process argument.
#
# The upstream scripts then write their arguments to logs/integrations.log
# on every call (main(), "Logging the call"), and an uncaught requests error
# names the request URL on stderr, which integratord copies to ossec.log.
# So every secret, and the path of a secret URL, is replaced with [secret]
# in stdout, stderr and the integration log.
import builtins
import os
import runpy
import sys
from urllib.parse import urlsplit

PREFIX = '@WAZUH_SECRET_'
SUFFIX = '@'
MASK = '[secret]'


def read_secret(directory, ident):
    if not ident or '/' in ident or ident.startswith('.'):
        sys.exit('integration-secrets: invalid secret token')
    with open(os.path.join(directory, ident)) as f:
        return f.read().rstrip('\n')


def fragments(value):
    """The secret and, for a URL, the part after the host, longest first."""
    out = {value}
    parts = urlsplit(value)
    if parts.scheme and parts.netloc:
        tail = value[value.index(parts.netloc) + len(parts.netloc):]
        if len(tail) >= 8:
            out.add(tail)
    return sorted(out, key=len, reverse=True)


class Redacting:
    def __init__(self, inner, secrets):
        self._inner = inner
        self._secrets = secrets

    def write(self, text):
        length = len(text)
        for secret in self._secrets:
            text = text.replace(secret, MASK)
        self._inner.write(text)
        return length

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._inner.close()
        return False

    def __getattr__(self, name):
        return getattr(self._inner, name)


def main(argv):
    if len(argv) < 3:
        sys.exit('usage: integration-secrets.py <secrets dir> <script> [arguments]')
    directory, script, args = argv[1], argv[2], argv[3:]

    secrets = []
    for i, arg in enumerate(args):
        if arg.startswith(PREFIX) and arg.endswith(SUFFIX) and len(arg) > len(PREFIX) + len(SUFFIX):
            value = read_secret(directory, arg[len(PREFIX):-len(SUFFIX)])
            args[i] = value
            secrets.extend(fragments(value))
    secrets = sorted(set(secrets), key=len, reverse=True)

    if secrets:
        sys.stdout = Redacting(sys.stdout, secrets)
        sys.stderr = Redacting(sys.stderr, secrets)
        plain_open = builtins.open

        def redacting_open(file, mode='r', *a, **k):
            f = plain_open(file, mode, *a, **k)
            if any(c in mode for c in 'wax') and 'b' not in mode \
                    and os.path.basename(os.fspath(file)) == 'integrations.log':
                return Redacting(f, secrets)
            return f

        builtins.open = redacting_open

    sys.argv = [script] + args
    sys.path.insert(0, os.path.dirname(script))
    runpy.run_path(script, run_name='__main__')


if __name__ == '__main__':
    main(sys.argv)
