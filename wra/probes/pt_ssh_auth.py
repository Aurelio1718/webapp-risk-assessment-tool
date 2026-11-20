"""PT verifier: SSH password authentication offered.

Asks the server which authentication methods it accepts (PreferredAuthentications=none): no password,
key or username of a real account is sent. The probe user name is fictitious.

OpenSSH >= 9.8 (PerSourcePenalties) temporarily refuses the auditor's IP after the external phase
(ssh-audit, Nuclei): a refused connection is retried with increasing waits before giving up.
"""
from __future__ import annotations

import re
import shutil
import time
from urllib.parse import urlsplit

from ..pentest import PT_CONFIRMED, PT_NOT_CONFIRMED, PT_NOT_TESTED, Verifier
from ..runner import ToolRunner

METHODS = re.compile(r"Permission denied \(([^)]*)\)")
PROBE_USER = "wra-pt-noauth"
REFUSED = re.compile(r"kex_exchange_identification|Connection reset|Connection closed|Connection refused", re.I)
RETRY_WAITS = (15, 30, 60)       # seconds; PerSourcePenalties are short for unauthenticated connections


class SshPasswordAuthVerifier(Verifier):
    name = "pt-ssh-auth-methods"
    check_ids = ("ssh-password-auth",)
    order = 20
    sleep = staticmethod(time.sleep)

    def applicable(self, ctx):
        if shutil.which("ssh") is None:
            return False, "OpenSSH client (ssh) not found in PATH"
        return super().applicable(ctx)

    def verify(self, ctx, f):
        p = urlsplit(f.element)
        # Host key not checked on purpose: nothing secret is sent and the connection never authenticates.
        cmd = ["ssh", "-p", str(p.port or 22), "-o", "PreferredAuthentications=none", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
               "-o", "LogLevel=ERROR", f"{PROBE_USER}@{p.hostname}", "exit"]
        log = []
        for wait in (0, *RETRY_WAITS):
            if wait:
                log.append(f"# connection refused (sshd penalty?): retrying in {wait}s")
                self.sleep(wait)
            res = ToolRunner.execute(cmd, timeout=30)
            log.append(f"$ {' '.join(cmd)}\n# {res.summary()}\n{res.stderr}{res.stdout}")
            m = METHODS.search(res.stderr)
            if m or not REFUSED.search(res.stderr):
                break
        ev = "\n".join(log)
        if not m:
            return PT_NOT_TESTED, "could not read the authentication methods from the server reply", ev
        methods = [x.strip() for x in m.group(1).split(",")]
        if "password" in methods or "keyboard-interactive" in methods:
            return PT_CONFIRMED, f"server offers {', '.join(methods)}: online password guessing is possible", ev
        return PT_NOT_CONFIRMED, f"server offers only {', '.join(methods)}", ev
