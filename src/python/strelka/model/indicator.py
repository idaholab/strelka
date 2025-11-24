from __future__ import annotations
import enum
from ipaddress import IPv4Address, IPv6Address
import re
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Final,
    Generic,
    Iterator,
    Literal,
    TypeVar,
    Union,
    Unpack,
    cast,
)
import urllib.parse
from urllib.parse import ParseResult as ParsedUrl

from pydantic import ConfigDict, Discriminator, model_validator
import validators

from ..auxiliary import indicators
from .base import Model
from .serialize import serialize
from .types import AnyPath, MACAddress, ScannerKey


__all__ = (
    "Indicator",
    "IndicatorParseError",
    "IndicatorType",
    "DomainNameIndicator",
    "EmailAddrIndicator",
    "IPv4AddrIndicator",
    "IPv6AddrIndicator",
    "MACAddrIndicator",
    "URLIndicator",
    "DirectoryIndicator",
    "FileIndicator",
    "PathIndicator",
    "MD5Indicator",
    "SHA1Indicator",
    "SHA256Indicator",
    "SHA384Indicator",
    "SHA512Indicator",
    "SsdeepIndicator",
    "TLSHIndicator",
)


_T = TypeVar("_T")


TLSH_RE: Final = re.compile(r"^(T1[0-9a-fA-F]{70})$")
SSDEEP_RE: Final = re.compile(r"^(\d+(?::[0-9a-zA-Z/+]+){2})(?:,.*)?$")


class IndicatorType(enum.StrEnum):
    """
    The possible types of IOCs, based on those defined by the Elastic Common Schema.

    Related:
        https://www.elastic.co/docs/reference/ecs/ecs-threat
    """

    artifact = "artifact"
    autonomous_system = "autonomous-system"
    directory = "directory"
    domain_name = "domain-name"
    email_addr = "email-addr"
    file = "file"
    ipv4_addr = "ipv4-addr"
    ipv6_addr = "ipv6-addr"
    mac_addr = "mac-addr"
    md5 = "md5"
    mutex = "mutex"
    path = "path"
    port = "port"
    process = "process"
    sha1 = "sha1"
    sha256 = "sha256"
    sha384 = "sha384"
    sha512 = "sha512"
    software = "software"
    ssdeep = "ssdeep"
    tlsh = "tlsh"
    url = "url"
    user_account = "user-account"
    windows_registry_key = "windows-registry-key"
    x509_certificate = "x509-certificate"


class IndicatorParseError(Exception):
    pass


AnyIndicator = None


class Indicator(
    Model,
    Generic[_T],
    frozen=True,
    sort_keys=("type", "value", "scanner"),
):
    __subclasses: ClassVar[list[type[Indicator]]] = []
    __subclasses_by_type: ClassVar[dict[str, type[Indicator]]] = {}

    type: IndicatorType | str
    value: _T
    scanner: ScannerKey | None = None

    def __init_subclass__(cls, **kwargs: Unpack[ConfigDict]) -> None:
        global AnyIndicator
        super().__init_subclass__(**kwargs)
        if (cls.parse.__func__ is not Indicator.parse.__func__) and (
            t := getattr(cls, "type", None)
        ):
            Indicator.__subclasses.append(cls)
            AnyIndicator = (
                Annotated[
                    Union[*Indicator.__subclasses],
                    Discriminator("type"),
                ]
                | Indicator
            )
            Indicator.__subclasses_by_type[t] = cls

    @model_validator(mode="after")
    @staticmethod
    def _validate(this: Indicator) -> Indicator:
        # make sure we always consider our type to be set so it gets serialized
        this.model_fields_set.update({"type"})
        return this

    @property
    def key(self) -> str:
        return getattr(self.type, "name", self.type)

    def __repr__(self) -> str:
        return f"{self.key}({serialize(self.value, as_json=False)})"

    @classmethod
    def parse(
        cls,
        value: Any,
        scanner: Any = None,
        type: Any = None,
    ) -> Iterator[Indicator]:
        # if we weren't given anything to validate, then just bail now
        if value is None:
            return

        if isinstance(value, Indicator):
            yield value
            return

        # decode anything given to us as bytes, since most of the indicator validators
        # don't support bytes objects cleanly
        if isinstance(value, bytes):
            value = value.decode()

        # if we were explicitly given a type, try to get a subclass for it and parse
        # using that; if tha fails, assume the scanner knew what it was talking about
        # and create a generic-typed indicator with our value/scanner
        if type:
            if subcls := cls.__subclasses_by_type.get(type):
                try:
                    yield from subcls.parse(value, scanner)
                    return
                except IndicatorParseError:
                    pass
            yield cls(type=type, value=value, scanner=scanner)
            return

        # no type given, instead attempt to guess by walking through our subclasses and
        # trying to parse with each until we (hopefully) find one that succeeds
        matched = False
        for subcls in cls.__subclasses:
            try:
                for result in subcls.parse(value, scanner):
                    matched = True
                    yield result
            except IndicatorParseError:
                pass

        # try serializating our value, and if we got something new from that, recurse
        # using the new value
        simplified = serialize(value, as_json=False)
        if simplified is not value and simplified != value:
            try:
                for result in cls.parse(value, scanner):
                    matched = True
                    yield result
            except IndicatorParseError:
                pass

        # if we failed to generate any matches, raise an exception
        if not matched:
            raise IndicatorParseError(value)


class _SimpleIndicator(Indicator[str], frozen=True):
    validator: ClassVar[Callable]

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=None) -> Iterator[Indicator]:
        if not isinstance(value, str) or not cls.validator(value):
            raise IndicatorParseError
        yield cls(
            type=cls.model_fields["type"].get_default(),
            value=value,
            scanner=scanner,
        )


class _NetworkAddressIndicator(Indicator[_T], frozen=True):
    address_type: ClassVar
    address_split: ClassVar[Callable[[str], tuple[str, int | None]]]

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=None) -> Iterator[Indicator]:
        if cls.address_type is not str and isinstance(value, cls.address_type):
            yield cls(type=type, value=value, scanner=scanner)
        elif isinstance(value, str):
            try:
                addr, port = cls.address_split(value)
            except ValueError:
                raise IndicatorParseError from None
            else:
                if port:
                    yield URLIndicator(value=value, scanner=scanner)
                yield cls.model_validate(
                    {
                        "value": cast(_T, cls.address_type(addr)),
                        "scanner": scanner,
                    }
                )
        else:
            raise IndicatorParseError


class URLIndicator(Indicator[str], frozen=True):
    type: Literal[IndicatorType.url] = IndicatorType.url

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=type) -> Iterator[Indicator]:
        if not isinstance(value, ParsedUrl):
            if not isinstance(value, str) or not validators.url(value):
                raise IndicatorParseError
            value = urllib.parse.urlparse(value)
        yield cls(value=value.geturl(), scanner=scanner)
        yield from Indicator.parse(value.netloc.split(":", 1)[0], scanner)


class MACAddrIndicator(Indicator[MACAddress], frozen=True):
    type: Literal[IndicatorType.mac_addr] = IndicatorType.mac_addr

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=type) -> Iterator[Indicator]:
        if isinstance(value, MACAddress):
            yield cls(value=value, scanner=scanner)
        elif isinstance(value, str):
            if not validators.mac_address(value):
                raise IndicatorParseError
            yield cls(value=MACAddress(value), scanner=scanner)
        else:
            raise IndicatorParseError


class IPv4AddrIndicator(_NetworkAddressIndicator[IPv4Address], frozen=True):
    address_type: ClassVar = IPv4Address
    address_split: ClassVar = indicators.ipv4.split
    type: Literal[IndicatorType.ipv4_addr] = IndicatorType.ipv4_addr


class IPv6AddrIndicator(_NetworkAddressIndicator[IPv6Address], frozen=True):
    address_type: ClassVar = IPv6Address
    address_split: ClassVar = indicators.ipv6.split
    type: Literal[IndicatorType.ipv6_addr] = IndicatorType.ipv6_addr


class DomainNameIndicator(Indicator[str], frozen=True):
    type: Literal[IndicatorType.domain_name] = IndicatorType.domain_name

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=type) -> Iterator[Indicator]:
        try:
            domain, port = indicators.domain.split(value)
        except ValueError:
            raise IndicatorParseError from None
        else:
            if port:
                yield URLIndicator(value=value, scanner=scanner)
            for domain in set(indicators.expand_idna_domain(domain)):
                yield cls(type=type, value=domain, scanner=scanner)


class EmailAddrIndicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.email
    type: Literal[IndicatorType.email_addr] = IndicatorType.email_addr

    @classmethod
    def parse(cls, value: Any, scanner: Any = None, type=type) -> Iterator[Indicator]:
        if isinstance(value, str):
            yield from super().parse(value.removeprefix("mailto:"), scanner, type)
        yield from super().parse(value, scanner, type)


class MD5Indicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.md5
    type: Literal[IndicatorType.md5] = IndicatorType.md5


class SHA1Indicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.sha1
    type: Literal[IndicatorType.sha1] = IndicatorType.sha1


class SHA256Indicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.sha256
    type: Literal[IndicatorType.sha256] = IndicatorType.sha256


class SHA384Indicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.sha384
    type: Literal[IndicatorType.sha384] = IndicatorType.sha384


class SHA512Indicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = validators.sha512
    type: Literal[IndicatorType.sha512] = IndicatorType.sha512


class TLSHIndicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = TLSH_RE.match
    type: Literal[IndicatorType.tlsh] = IndicatorType.tlsh


class SsdeepIndicator(_SimpleIndicator, frozen=True):
    validator: ClassVar = SSDEEP_RE.match
    type: Literal[IndicatorType.ssdeep] = IndicatorType.ssdeep


class PathIndicator(Indicator, frozen=True):
    type: Literal[IndicatorType.path] = IndicatorType.path
    value: AnyPath | str


class FileIndicator(Indicator, frozen=True):
    type: Literal[IndicatorType.file] = IndicatorType.file
    value: AnyPath | str


class DirectoryIndicator(Indicator, frozen=True):
    type: Literal[IndicatorType.directory] = IndicatorType.directory
    value: AnyPath | str
