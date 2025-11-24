from __future__ import annotations
import datetime
from typing import NamedTuple, Self

from opentelemetry import context

from ..model import Date, File


class Client(NamedTuple):
    source: str | None
    client: str | None


class Task(NamedTuple):
    id: str
    submitted_at: Date
    expire_at: Date
    traceparent: str | None
    client: Client
    file: File

    @staticmethod
    def _now() -> datetime.datetime:
        return datetime.datetime.now(datetime.UTC)

    @classmethod
    def for_file(cls, file: File, expire_at: Date) -> Self:
        return cls(
            id=file.pointer,
            submitted_at=cls._now(),
            expire_at=expire_at,
            traceparent=None,
            client=Client("file", None),
            file=file,
        )

    def __str__(self) -> str:
        return f"task[{self.id}]"

    def __repr__(self) -> str:
        return "<{} id={} expire_at={} file={!r}>".format(
            type(self).__name__,
            self.id,
            self.expire_at,
            self.file,
        )

    @property
    def expired(self) -> bool:
        return self._now() >= self.expire_at

    @property
    def remaining_seconds(self) -> datetime.timedelta:
        return self.expire_at - self._now()

    @property
    def event_list(self) -> str:
        return f"event:{self.id}"

    def attach_trace_context(self) -> None:
        if self.traceparent:
            from opentelemetry.trace.propagation.tracecontext import (
                TraceContextTextMapPropagator,
            )

            carrier = {"traceparent": self.traceparent}
            ctx = TraceContextTextMapPropagator().extract(carrier)
            context.attach(ctx)
