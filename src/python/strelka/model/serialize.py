from __future__ import annotations
import dataclasses
import datetime
import enum
import functools
import json
from typing import (
    Annotated,
    Any,
    Counter,
    List,
    Literal,
    Mapping,
    Set,
    Tuple,
    TypedDict,
    overload,
)

from pydantic import PlainSerializer, PlainValidator, SerializationInfo, TypeAdapter
import pydantic.errors

from ..util import safe_decode
from .types import AnyPath, IPv4Address, IPv6Address, MACAddress, ParsedUrl, UUID


__all__ = ("serialize",)


class SerializationContext(TypedDict):
    convert_bytes: bool
    simplify: bool


def _serialize_value(value: Any, info: SerializationInfo[SerializationContext]) -> Any:
    _s = functools.partial(_serialize_value, info=info)

    convert_bytes = (info.context or {}).get("convert_bytes")
    simplify = (info.context or {}).get("simplify")

    if simplify and isinstance(value, enum.StrEnum):
        return value.value
    elif simplify and isinstance(value, ParsedUrl):
        return value.geturl()
    elif isinstance(value, str):
        return value
    elif isinstance(value, bytes):
        if convert_bytes:
            return safe_decode(value)
        return value

    elif isinstance(value, Set):
        return _s(sorted(value))
    elif isinstance(value, Mapping):
        return {_s(k): _s(v) for k, v in value.items()}
    elif isinstance(value, List):
        return [_s(e) for e in value]
    elif isinstance(value, Tuple):
        return tuple(_s(e) for e in value)
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _s(dataclasses.asdict(value))

    elif simplify:
        if isinstance(value, Counter):
            return _s(dict(value))
        elif isinstance(value, enum.Flag):
            return sorted(value.name.split("|")) if value.name else []
        elif isinstance(value, enum.Enum):
            return _s(value.name)
        elif isinstance(value, UUID):
            return str(value)
        elif isinstance(value, datetime.datetime):
            return value.isoformat()
        elif isinstance(value, datetime.timedelta):
            return value.total_seconds()
        elif isinstance(value, IPv4Address | IPv6Address | MACAddress):
            return str(value)
        elif isinstance(value, AnyPath):
            return str(value)

    try:
        result = TypeAdapter(type(value)).dump_python(
            value,
            by_alias=info.by_alias,
            exclude_unset=info.exclude_unset,
            exclude_defaults=info.exclude_defaults,
            exclude_none=info.exclude_none,
            exclude_computed_fields=info.exclude_computed_fields,
            round_trip=info.round_trip,
            serialize_as_any=info.serialize_as_any,
        )
        if result is value or result == value:
            return value
        return _s(result)
    except (pydantic.errors.PydanticSchemaGenerationError, RecursionError):
        return value


def _validate_value(value: Any) -> Any:
    return value


_AnyValue = Annotated[
    Any, PlainSerializer(_serialize_value), PlainValidator(_validate_value)
]
_AnyValueAdapter = TypeAdapter(_AnyValue)


@overload
def serialize(
    what: Any,
    *,
    as_json: Literal[True] = True,
    simplify: Literal[True] = True,
    convert_bytes: Literal[True] = True,
    minify_json: bool = True,
    exclude_unset: bool = True,
    exclude_defaults: bool = False,
    exclude_none: bool = False,
    exclude_computed_fields: bool = False,
) -> str: ...


@overload
def serialize(
    what: Any,
    *,
    as_json: Literal[False] = False,
    simplify: bool = True,
    convert_bytes: bool = True,
    minify_json: bool = True,
    exclude_unset: bool = True,
    exclude_defaults: bool = False,
    exclude_none: bool = False,
    exclude_computed_fields: bool = False,
) -> Any: ...


def serialize(
    what: Any,
    *,
    convert_bytes: bool = True,
    simplify: bool = True,
    as_json: bool = True,
    minify_json: bool = True,
    exclude_unset: bool = True,
    exclude_defaults: bool = False,
    exclude_none: bool = False,
    exclude_computed_fields: bool = False,
) -> Any:
    result = _AnyValueAdapter.dump_python(
        what,
        context=SerializationContext(
            convert_bytes=convert_bytes,
            simplify=simplify,
        ),
        exclude_unset=exclude_unset,
        exclude_defaults=exclude_defaults,
        exclude_none=exclude_none,
        exclude_computed_fields=exclude_computed_fields,
    )
    if as_json:
        if minify_json:
            return json.dumps(result, indent=None, separators=(",", ":"))
        else:
            return json.dumps(result)
    else:
        return result
