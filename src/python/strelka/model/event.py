from __future__ import annotations
import datetime
import sys
import traceback
from typing import Annotated, Any, TypeVar

from pydantic import (
    BaseModel,
    Field,
    PlainSerializer,
    PlainValidator,
    computed_field,
    model_validator,
)

from ..util import now, typename
from .base import Model
from .file import File
from .indicator import Indicator
from .rule import Rule
from .types import Date, ScannerKey


__all__ = (
    "Event",
    "ExceptionInfo",
    "FileResults",
    "ScannerResults",
)


_T = TypeVar("_T")
_ExceptionType = Annotated[
    BaseException,
    PlainSerializer(lambda _: None),
    PlainValidator(lambda v: v),
]
_ObjectSet = Annotated[
    set[_T],
    PlainSerializer(lambda v: sorted(v)),
]


class ExceptionInfo(
    Model,
    frozen=True,
    sort_keys=("timestamp", "qualified_name", "message"),
):
    @staticmethod
    def _current_exc() -> BaseException:
        if (exc := sys.exception()) is None:
            raise RuntimeError("no current exception")
        return exc

    timestamp: Date = Field(repr=False, default_factory=now)
    exception: _ExceptionType = Field(exclude=True, default_factory=_current_exc)
    scanner: ScannerKey | None = None
    flag: str | None = None

    @model_validator(mode="after")
    @staticmethod
    def _validate(this: ExceptionInfo) -> ExceptionInfo:
        # force timestamp to be considered "set" so it will be output
        this.model_fields_set.add("timestamp")
        return this

    @computed_field
    def qualified_name(self) -> str:
        return typename(self.exception)

    @computed_field
    def name(self) -> str:
        return type(self.exception).__name__

    @computed_field
    def message(self) -> str:
        return str(self.exception)

    @computed_field
    def traceback(self) -> str:
        return "\n".join(traceback.format_exception(self.exception, limit=-10))


class ScannerResults(Model, frozen=True, extra="allow"):
    scanner: str
    elapsed: float

    # XXX: extra fields are allowed, so this is populated with additional fields as a
    #      given scanner sees fit


class FileResults(Model, frozen=True):
    file: File
    scan: dict[str, ScannerResults]

    children: list[File]
    related: set[Indicator]
    rules: list[Rule]
    flags: set[str]
    exceptions: set[ExceptionInfo]


class Event(BaseModel):
    timestamp: Date = Field(alias="@timestamp", default_factory=now)
    expire_at: Annotated[Date, Field(exclude=True)] = datetime.datetime.max

    file: File

    children: Annotated[list[File], Field(exclude=True)] = []
    exceptions: _ObjectSet[ExceptionInfo] = set()
    flags: set[str] = set()
    related: _ObjectSet[Indicator] = set()
    rules: list[Rule] = []
    scan: dict[str, Any] = {}
    scanners: set[str] = set()

    @model_validator(mode="after")
    @staticmethod
    def _validate(this: ExceptionInfo) -> ExceptionInfo:
        this.model_fields_set.update(
            {"exceptions", "flags", "related", "rules", "scan", "scanners"}
        )
        return this

    def update(self, results: FileResults) -> None:
        assert self.file.tree.node == results.file.tree.node
        self.children.extend(results.children)
        self.exceptions.update(results.exceptions)
        self.flags.update(results.flags)
        self.related.update(results.related)
        self.rules.extend(results.rules)
        self.scan.update(results.scan)
        self.scanners.update(results.scan.keys())
