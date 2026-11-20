"""Shared helpers for probes that wrap third-party tools."""
from __future__ import annotations

import os
import socket
from pathlib import Path


def cache_dir(name: str) -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    p = base / "wra" / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def tail(text: str, n: int = 15) -> str:
    return "\n".join((text or "").strip().splitlines()[-n:])


def save_run(ctx, phase: str, name: str, res) -> None:
    """Keep the exact command and the tool's console output in raw/ (methodology evidence)."""
    ctx.store.write_raw(phase, f"{name}.log",
                        f"$ {' '.join(res.cmd)}\n# {res.summary()}\n\n--- stdout ---\n{res.stdout}\n--- stderr ---\n{res.stderr}")
