from __future__ import annotations
from typing import Any

from .base import Model
from .indicator import Indicator
from .types import EnsureList, EnsureSet, ScannerKey


__all__ = ("Rule", "Technique")


class Technique(Model, frozen=True, sort_keys=("source", "id", "name")):
    source: str | None = None
    id: str | None = None
    name: str | None = None
    reference: EnsureSet[str] | None = None


class Rule(Model, frozen=True, sort_keys=("uuid", "name", "provider", "version")):
    scanner: ScannerKey | None = None

    author: EnsureList[str] | None = None
    category: str | None = None
    description: str | None = None
    id: Any | None = None
    license: str | None = None
    name: str | None = None
    provider: str | None = None
    reference: EnsureSet[str] | None = None
    ruleset: str | None = None
    uuid: Any | None = None
    version: str | None = None

    matched: EnsureSet[Indicator] = set()
    tags: EnsureSet[str] = set()
    techniques: EnsureSet[Technique] = set()
