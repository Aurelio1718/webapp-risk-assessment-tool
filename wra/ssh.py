"""Read-only, agentless SSH access to the target host.

Every remote command is a constant defined in wra's own code; data coming from the target is
never interpolated into a command.
"""
from __future__ import annotations

import re

from .runner import ToolResult, ToolRunner

_SAFE_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.IGNORECASE)
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.:\[\]-]+$")


class SSHError(Exception):
    pass


class SSHClient:
    def __init__(self, cfg):
        if not _SAFE_USER.match(cfg.user or ""):
            raise SSHError(f"invalid ssh.user {cfg.user!r}")
        if not _SAFE_HOST.match(cfg.host or "") or cfg.host.startswith("-"):
            raise SSHError(f"invalid ssh.host {cfg.host!r}")
        self.cfg = cfg

    def base_cmd(self) -> list[str]:
        c = self.cfg
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={c.known_hosts}",
            "-o", f"ConnectTimeout={c.connect_timeout}",
            "-o", "IdentitiesOnly=yes",
            "-o", "LogLevel=ERROR",
            "-i", c.key_path,
            "-p", str(c.port),
            "-l", c.user,
            "--", c.host,
        ]

    def run(self, remote_cmd: str, timeout: int = 120, input_text: str | None = None) -> ToolResult:
        """input_text goes to the remote script's stdin (used for secrets: never on a command line)."""
        return ToolRunner.execute(self.base_cmd() + [remote_cmd], timeout=timeout, input_text=input_text)

    def target(self) -> str:
        return f"{self.cfg.user}@{self.cfg.host}:{self.cfg.port}"
