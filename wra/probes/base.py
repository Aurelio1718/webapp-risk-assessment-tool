"""Probe interface. One probe = one source of information.

To add a source, drop a module in wra/probes/ that defines a subclass of Probe: it is discovered
automatically.
"""
from __future__ import annotations

from ..access import rank
from ..finding import Finding


class Probe:
    name: str = "probe"
    phase: str = "external"            # external | pentest | internal
    source: str = "wra"                # label shown in the 'sources' column
    requires_access: str = "none"      # none | user | privileged
    requires_active: bool = False      # needs --active
    tool: str | None = None            # key in [images] when a third-party tool is used
    order: int = 50                    # execution order inside a phase

    def element(self, ctx) -> str:
        return ctx.config.target.url

    def gate(self, ctx) -> tuple[bool, str]:
        """Generic gating: active flag, access level, tool availability."""
        if self.requires_active and not ctx.active:
            return False, "requires --active"
        if rank(ctx.level) < rank(self.requires_access):
            return False, f"requires access: {self.requires_access} (available: {ctx.level})"
        if self.tool:
            status, detail = ctx.runner.image_status(self.tool)
            if status == "FAIL":
                return False, f"tool '{self.tool}' unavailable: {detail}"
        return self.applicable(ctx)

    def applicable(self, ctx) -> tuple[bool, str]:
        """Probe-specific applicability (e.g. stack detection). Override when needed."""
        return True, "applicable"

    def run(self, ctx) -> list[Finding]:
        raise NotImplementedError
