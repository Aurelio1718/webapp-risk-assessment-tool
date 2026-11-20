"""Automatic discovery of probe modules in this package."""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import Probe


def discover(phase: str | None = None) -> list[Probe]:
    probes: list[Probe] = []
    for mod in pkgutil.iter_modules(__path__):
        if mod.name.startswith("_") or mod.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{mod.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Probe) and obj is not Probe and obj.__module__ == module.__name__:
                p = obj()
                if phase is None or p.phase == phase:
                    probes.append(p)
    probes.sort(key=lambda p: (p.order, p.name))
    return probes
