from __future__ import annotations
import re
from types import GenericAlias
from typing import Annotated, Any, ClassVar
import typing

import packaging.specifiers
import packaging.version
from pydantic import (
    AnyUrl,
    BaseModel,
    JsonValue,
    PlainSerializer,
    PlainValidator,
    model_validator,
)


def _parse_version(value: str | packaging.version.Version) -> Version:
    if isinstance(value, packaging.version.Version):
        return value
    return packaging.version.parse(str(value))


Version = Annotated[
    packaging.version.Version,
    PlainValidator(_parse_version),
    PlainSerializer(str),
]

SpecifierSet = Annotated[
    packaging.specifiers.SpecifierSet,
    PlainValidator(packaging.specifiers.SpecifierSet),
    PlainSerializer(str),
]


def _validate_typename(value: str) -> type[JsonValue]:
    temp = lambda: None  # noqa: E731
    temp.__annotations__["return"] = value
    return typing.get_type_hints(temp)["return"]


def _serialize_typename(value: Any) -> str:
    if isinstance(value, GenericAlias):
        return str(value)
    elif isinstance(value, type):
        if value.__module__ in {"builtins"}:
            return value.__qualname__
        else:
            return ".".join([value.__module__, value.__qualname__])
    elif isinstance(value, str):
        return value
    else:
        raise TypeError(f"unsure how to serialize type: {value!r}")


JsonValueTypeName = Annotated[
    type,
    PlainValidator(_validate_typename),
    PlainSerializer(_serialize_typename),
]


class Dependency(BaseModel, frozen=True):
    PATTERN: ClassVar = re.compile(r"^([_A-Za-z][-_A-Za-z0-9]*)\s*(.+)?$")

    name: str
    specifier: SpecifierSet | None = None

    @model_validator(mode="wrap")
    @classmethod
    def _validate(cls, value: Any, handler) -> Dependency:
        if isinstance(value, Dependency):
            return value
        if isinstance(value, dict):
            return handler(value)
        if (m := cls.PATTERN.match(str(value))) is None:
            raise ValueError("invalid dependency specification")
        return handler(
            {
                "name": m.group(1),
                "specifier": m.group(2),
            }
        )

    def __repr__(self) -> str:
        return "{}({!s})".format(type(self).__name__, self)

    def __str__(self) -> str:
        return "{}{}".format(self.name, self.specifier or "")


class OptionDef(BaseModel, frozen=True):
    type: JsonValueTypeName
    description: str | None = None
    examples: list[Any] = []
    default: Any = ...
    required: bool | None = None


class ScannerInfo(BaseModel, frozen=True):
    example_rules: list[dict] = []
    options: dict[str, OptionDef] = {}


class Metadata(BaseModel, frozen=True, extra="allow"):
    name: str
    version: Version
    summary: str = ""
    description: str = ""
    dependencies: list[Dependency] = []
    authors: list[str] = []
    urls: list[AnyUrl] = []
    tags: list[str] = []
    mimetypes: list[str] = []
    scanners: dict[str, ScannerInfo] = {}

    def __repr__(self) -> str:
        return "{}({!s})".format(type(self).__name__, self)

    def __str__(self) -> str:
        return "{}@{}".format(self.name, self.version)
