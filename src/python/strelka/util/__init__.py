from __future__ import annotations
import datetime
import os
from typing import Any, Final, Iterator, Type, overload

import inflection


BytesLike = bytes | bytearray | memoryview


class _MISSING:
    def __gt__(self, _: Any) -> bool:
        return False

    def __eq__(self, other: Any) -> bool:
        return other is self

    def __bool__(self) -> bool:
        return False

    def __str__(self) -> str:
        return "<MISSING>"


MISSING: Final = _MISSING()


def typename(what: Type | Any) -> str:
    if isinstance(what, type):
        return "{}.{}".format(what.__module__, what.__qualname__)
    else:
        return typename(type(what))


def unquote(data: str, ends: str) -> str:
    if not (0 < len(ends) <= 2):
        raise ValueError("ends must be one or two characters")
    if len(ends) == 1:
        ends = ends * 2
    b, e = ends
    return data.removeprefix(b).removesuffix(e)


def ensure_string(what: Any) -> str:
    if isinstance(what, os.PathLike):
        what = os.fspath(what)
    if isinstance(what, bytes):
        what = what.decode()
    return str(what)


@overload
def chunk_data(data: BytesLike, chunk_size: int) -> Iterator[bytes]: ...
@overload
def chunk_data(data: str, chunk_size: int) -> Iterator[str]: ...


def chunk_data(data: BytesLike | str, chunk_size: int) -> Iterator[bytes | str]:
    for c in range(0, len(data), chunk_size):
        if isinstance(data, str):
            yield data[c : c + chunk_size]
        else:
            yield bytes(data[c : c + chunk_size])


def match_quantity(quantity: int, noun: str) -> tuple[int, str]:
    if quantity == 1:
        return quantity, inflection.singularize(noun)
    else:
        return quantity, inflection.pluralize(noun)


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def safe_decode(what: bytes | str, encoding: str = "utf-8") -> str:
    if isinstance(what, str):
        return what
    return what.decode(encoding=encoding, errors="replace")
