from __future__ import annotations
from typing import Any

from .base import Model
from .indicator import Indicator
from .types import EnsureList, EnsureSet, ScannerKey


__all__ = ("Rule",)


class Rule(Model, frozen=True):
    scanner: ScannerKey | None = None

    author: EnsureList[str] | None = None
    category: str | None = None
    description: str | None = None
    id: Any | None = None
    license: str | None = None
    name: str | None = None
    provider: str | None = None
    reference: str | None = None
    ruleset: str | None = None
    uuid: Any | None = None
    version: str | None = None

    matched: EnsureSet[Indicator] = set()
