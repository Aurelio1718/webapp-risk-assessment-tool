"""Run third-party tools in pinned containers (podman/docker) or from PATH (local mode).

Security: commands are always argument lists (never shell=True) and target output is never
interpolated into a command line.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass

log = logging.getLogger("wra.runner")

# tool key in [images] -> binary name for local mode
TOOLS = {
    "nmap": "nmap",
    "zap": "zap-baseline.py",
    "nuclei": "nuclei",
    "ssh-audit": "ssh-audit",
    "trivy": "trivy",
    "semgrep": "semgrep",
    "trufflehog": "trufflehog",
    "sqlmap": "sqlmap",
    "ffuf": "ffuf",
}


class RunnerError(Exception):
    """Raised when a tool cannot be run (missing image, unpinned image, missing engine)."""


@dataclass
class ToolResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    def summary(self) -> str:
        return f"rc={self.returncode} in {self.duration:.1f}s" + (" (timeout)" if self.timed_out else "")


def is_pinned(ref: str) -> bool:
    return "@sha256:" in ref and "REPLACE_ME" not in ref


class ToolRunner:
    def __init__(self, runtime, images: dict[str, str], tool_args: dict[str, list[str]]):
        self.runtime = runtime
        self.images = images
        self.tool_args = tool_args

    # ----- resolution -------------------------------------------------------------------------
    def image(self, tool: str) -> str:
        ref = self.images.get(tool, "").strip()
        if not ref or "REPLACE_ME" in ref:
            raise RunnerError(f"no image configured for '{tool}' in [images]")
        if not is_pinned(ref) and not self.runtime.allow_unpinned:
            raise RunnerError(f"image for '{tool}' is not pinned by digest ({ref}); set runtime.allow_unpinned=yes to override")
        return ref

    def local_binary(self, tool: str) -> str | None:
        return shutil.which(TOOLS.get(tool, tool))

    def uses_local(self, tool: str) -> bool:
        return self.runtime.mode == "local" and self.local_binary(tool) is not None

    def volume_suffix(self) -> str:
        opt = self.runtime.volume_opts
        if opt == "auto":
            return ":Z" if os.path.exists("/sys/fs/selinux/enforce") else ""
        if opt in ("z", "Z"):
            return f":{opt}"
        return ""

    # ----- command building -------------------------------------------------------------------
    def build(self, tool: str, args: list[str], mounts: list[tuple[str, str]] | None = None,
              workdir: str | None = None, entrypoint: str | None = None) -> list[str]:
        """Build the argv for a tool.

        mounts: (host_path, container_path). In local mode container paths found in args are
        rewritten to the corresponding host paths, so probes can use one set of arguments.
        """
        mounts = mounts or []
        if any(not isinstance(a, str) for a in args):
            raise RunnerError("tool arguments must be strings")
        if self.uses_local(tool):
            out = []
            for a in args:
                for host, cont in mounts:
                    if a == cont or a.startswith(cont.rstrip("/") + "/"):
                        a = host + a[len(cont):]
                        break
                out.append(a)
            binary = self.local_binary(tool)
            if entrypoint:
                found = shutil.which(entrypoint)
                if not found:
                    raise RunnerError(f"local mode: '{entrypoint}' not found in PATH")
                binary = found
            return [binary, *out]

        engine = self.runtime.engine
        if shutil.which(engine) is None:
            raise RunnerError(f"container engine '{engine}' not found in PATH")
        cmd = [engine, "run", "--rm", *self.runtime.extra_args, *self.tool_args.get(tool, [])]
        suffix = self.volume_suffix()
        for host, cont in mounts:
            cmd += ["-v", f"{os.path.abspath(host)}:{cont}{suffix}"]
        if workdir:
            cmd += ["-w", workdir]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        cmd.append(self.image(tool))
        cmd += args
        return cmd

    # ----- execution --------------------------------------------------------------------------
    @staticmethod
    def execute(cmd: list[str], timeout: int = 900, input_text: str | None = None) -> ToolResult:
        log.debug("exec: %s", " ".join(cmd))
        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                  timeout=timeout, input=input_text, shell=False, check=False)
            return ToolResult(cmd, proc.returncode, proc.stdout, proc.stderr, time.monotonic() - start)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return ToolResult(cmd, 124, out, err, time.monotonic() - start, timed_out=True)
        except FileNotFoundError as exc:
            return ToolResult(cmd, 127, "", str(exc), time.monotonic() - start)

    def run(self, tool: str, args: list[str], mounts=None, workdir=None, entrypoint=None,
            timeout: int = 900) -> ToolResult:
        return self.execute(self.build(tool, args, mounts, workdir, entrypoint), timeout=timeout)

    # ----- checks -----------------------------------------------------------------------------
    def engine_version(self) -> tuple[bool, str]:
        engine = self.runtime.engine
        if shutil.which(engine) is None:
            return False, f"{engine} not found in PATH"
        res = self.execute([engine, "--version"], timeout=30)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def image_status(self, tool: str) -> tuple[str, str]:
        """Return (status, detail) with status in PASS/WARN/FAIL."""
        if self.runtime.mode == "local" and self.local_binary(tool):
            return "PASS", f"local binary {self.local_binary(tool)}"
        ref = self.images.get(tool, "")
        if not ref or "REPLACE_ME" in ref:
            return "FAIL", "image not configured (REPLACE_ME)"
        pinned = is_pinned(ref)
        if shutil.which(self.runtime.engine) is None:
            return "FAIL", f"{self.runtime.engine} not found"
        res = self.execute([self.runtime.engine, "image", "inspect", "--format", "{{.Id}}", ref], timeout=30)
        if res.returncode != 0:
            return "FAIL", f"image not present locally: {ref} (pull it first)"
        if not pinned:
            return ("WARN" if self.runtime.allow_unpinned else "FAIL"), f"not pinned by digest: {ref}"
        return "PASS", ref.split("@")[0] + "@" + ref.split("@")[1][:19] + "..."
