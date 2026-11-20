"""Run context shared by commands and probes."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from . import access
from .runner import ToolRunner
from .ssh import SSHClient
from .store import RunStore

log = logging.getLogger("wra")


def default_out_dir(config) -> str:
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", config.target.host) or "target"
    return str(Path("reports") / host)


class Context:
    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.active = bool(getattr(args, "active", False))
        self.ceiling = getattr(args, "access_level", "auto") or "auto"
        self.store = RunStore(getattr(args, "out", None) or default_out_dir(config)).ensure()
        self.runner = ToolRunner(config.runtime, config.images, config.tool_args)
        self.source_path = getattr(args, "source", None) or ""
        self._ssh = None
        self._access = None

    @property
    def ssh(self) -> SSHClient | None:
        if self.ceiling == "none" or not self.config.ssh.enabled:
            return None
        if self._ssh is None:
            self._ssh = SSHClient(self.config.ssh)
        return self._ssh

    def access(self, refresh: bool = False) -> dict:
        """Detect (once) and return {'detected','ceiling','effective','details','facts'}."""
        if self._access is None or refresh:
            if self.ceiling == "none":
                detected, details, facts = "none", ["Access level forced to none (--access-level none)"], {}
            else:
                detected, details, facts = access.detect(self.ssh)
            self._access = {
                "detected": detected,
                "ceiling": self.ceiling,
                "effective": access.effective(detected, self.ceiling),
                "details": details,
                "facts": facts,
            }
            meta_view = {k: v for k, v in self._access.items() if k != "facts"}
            self.store.update_meta(access=meta_view)
        return self._access

    @property
    def level(self) -> str:
        return self.access()["effective"]
