from __future__ import annotations
import datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Iterable, List, Self, Set, TypeVar, cast
from urllib.parse import ParseResult as ParsedUrl
import uuid

import macaddress
from pydantic import PlainSerializer, PlainValidator
from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema as _cs
import validators


__all__ = (
    "AnyPath",
    "Date",
    "Duration",
    "Elapsed",
    "EnsureList",
    "EnsureSet",
    "MACAddress",
    "Octal",
    "ScannerKey",
    "UUID",
    "IPv4Address",
    "IPv6Address",
    "ParsedUrl",
)


_T = TypeVar("_T")


class EUI48(macaddress.EUI48):
    @classmethod
    def _validate(cls, value: str | macaddress.EUI48) -> Self:
        if isinstance(value, macaddress.EUI48):
            return cls(value)
        elif not validators.mac_address(value):
            raise ValueError("invalid MAC address format")
        return cls(value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        return _cs.json_or_python_schema(
            _cs.no_info_plain_validator_function(
                cls._validate,
                serialization=_cs.to_string_ser_schema(),
            ),
            _cs.no_info_plain_validator_function(cls._validate),
        )

    # XXX: this returns a LiteralString in the base, which... doesn't make sense?
    def __str__(self) -> str:  # type: ignore
        return self._address.to_bytes(self.size >> 3).hex(":")


def _validate_ensure_list(value: _T | Iterable[_T]) -> List[_T]:
    if isinstance(value, (str, bytes)):
        return [cast(_T, value)]
    elif isinstance(value, Iterable):
        return [*value]
    else:
        return [value]


def _validate_ensure_set(value: _T | Iterable[_T]) -> Set[_T]:
    if isinstance(value, (str, bytes)):
        return {cast(_T, value)}
    elif isinstance(value, Iterable):
        return {*value}
    else:
        return {value}


def _serialize_ensure_set(value: Iterable[_T]) -> List[_T]:
    try:
        return sorted(value)  # type: ignore
    except TypeError:
        return list(value)


def _scanner_key(value: Any) -> str:
    # XXX: must be a local import to not cause recursive imports
    from ..scanners import Scanner

    if isinstance(value, str):
        return value
    elif isinstance(value, Scanner):
        return value.key
    elif isinstance(value, type) and issubclass(value, Scanner):
        return value.key
    else:
        raise TypeError(f"value is not a string or Scanner: {value!r}")


AnyPath = PurePath | PurePosixPath | PureWindowsPath
Date = datetime.datetime
Duration = datetime.timedelta
Elapsed = Duration
EnsureList = Annotated[
    List[_T],
    PlainValidator(_validate_ensure_list),
]
EnsureSet = Annotated[
    Set[_T],
    PlainValidator(_validate_ensure_set),
    PlainSerializer(_serialize_ensure_set),
]
MACAddress = EUI48
Octal = Annotated[
    int,
    PlainSerializer(lambda v: f"0{v:o}"),
    PlainValidator(lambda v: v if isinstance(v, int) else int(v, 8)),
]
ScannerKey = Annotated[str, PlainValidator(_scanner_key)]
UUID = uuid.UUID
