from __future__ import annotations
from abc import ABCMeta, abstractmethod
import dataclasses
import datetime
import logging
import math
from pathlib import Path
import sys
import time
from types import EllipsisType
from typing import (
    Any,
    ClassVar,
    Hashable,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    TYPE_CHECKING,
    overload,
)
from typing_extensions import deprecated
import uuid
import itertools

import inflection
from opentelemetry import trace
from pydantic import BaseModel

from .. import backend  # noqa: F401
from ..exceptions import ScannerException, ScannerTimeout
from ..model import (
    Date,
    ExceptionInfo,
    File,
    FileResults,
    FileType,
    Hash,
    Indicator,
    Rule,
    ScannerResults,
)
from ..telemetry.traces import SpanCreatorMixin
from ..util.collections import ListCompatibleSet, dataclass_to_dict, filter_mapping
from ..util.files import find_executable
from ..util.timeout import timeout_after

if TYPE_CHECKING:
    from _typeshed import DataclassInstance
else:
    DataclassInstance = "_typeshed.DataclassInstance"


Options = Mapping[str, Any]
Expiration = float
UniqueKey = tuple[Hashable, ...]


class ScannerUtilMethods:
    @overload
    @staticmethod
    def evaluate_limit(value: int) -> int: ...

    @overload
    @staticmethod
    def evaluate_limit(value: float) -> float: ...

    @staticmethod
    def evaluate_limit(value: int | float) -> int | float:
        if isinstance(value, int):
            if value < 0:
                return sys.maxsize
            return value
        else:
            if value < 0:
                return math.inf
            return value

    @staticmethod
    def normalize_key(key: str, words: set[str] | None = None) -> str:
        for word in words or ():
            key = key.replace(word, word.title())
        return inflection.underscore(
            key.replace(" ", "_").replace("/", "_").replace(".", "_")
        )

    @staticmethod
    def find_executable(program: str, path: str | Path | None) -> str | None:
        return find_executable(program, path)


class Scanner(ScannerUtilMethods, SpanCreatorMixin, metaclass=ABCMeta):
    """Defines a scanner that scans File objects.

    Each scanner inherits this class and overrides methods (init and scan)
    to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in the scanner metadata.
        key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        qualified_key: String that contains the scanner's qualified metadata key.
            This is used to identify the scanner in IOC matches.
        event: Dictionary containing the result of scan
        backend_cfg: Dictionary that contains the parsed backend configuration.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
        coordinator: Redis client connection to the coordinator.
    """

    name: ClassVar[str]
    key: ClassVar[str]
    qualified_key: ClassVar[str]

    backend: backend.BaseBackend
    tracer: trace.Tracer

    file: File
    options: Options

    event: dict
    children: list[File]
    flags: ListCompatibleSet[str]
    exceptions: set[ExceptionInfo]
    related: set[Indicator]
    rules: list[Rule]
    expire_at: Date

    __child_keys: set[UniqueKey]

    def __init_subclass__(cls) -> None:
        # automatically populate common, class-specific fields that don't need
        # to be recalculated every time we instantiate the class; also allows
        # them to be used without having an instance
        cls.name = cls.__name__
        cls.key = inflection.underscore(cls.name.removeprefix("Scan"))
        cls.qualified_key = f"strelka.scanner.{cls.key}"

    def __init__(
        self,
        backend: backend.BaseBackend,
        tracer: trace.Tracer | None = None,
    ) -> None:
        self.backend = backend
        self.tracer = tracer or trace.get_tracer(__name__)

        self.clear()
        self.init()

    def init(self) -> None:
        """Overrideable init.

        This method can be used to setup non-scan-specific variables/resources
        that will be required during scanning.
        """

    def clear(self) -> None:
        """Overridable scan state clear method.

        Used to clear out event/file/flag/etc. scanner state after a scan has
        finished. Classes that override this should call `super().clear()` (in
        addition to clearing whatever scanner-specific state) to ensure that all
        scan-specific state is cleared.
        """

        self.file = File.EMPTY
        self.options = {}

        self.event = {}
        self.children = []
        self.__child_keys = set()
        self.flags = ListCompatibleSet()
        self.exceptions = set()
        self.related = set()
        self.rules = list()
        self.expire_at = datetime.datetime.max

    @abstractmethod
    def scan(
        self,
        data: bytes,
        file: File,
        options: Options,
        expire_at: Date,
    ) -> None | dict[str, Any] | DataclassInstance | BaseModel:
        """Overrideable scan method.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        Returns:
            - nothing if the scanner directly updates the internal event
            - a dictionary containing event data to update the internal event
            - a dataclass instance, which is converted to a dictionary and used
              to update the internal event
        """
        ...

    @property
    def scanner_timeout(self) -> float:
        return self.options.get(
            "scanner_timeout",
            self.backend.config.get("limits.scanner", 60.0),
        )

    @property
    def trace_attributes(self) -> Iterator[tuple[str, Any]]:
        yield "scanner.name", self.name
        yield "scanner.timeout", self.scanner_timeout

    def scan_wrapper(
        self,
        data: bytes,
        file: File,
        options: Options,
        expire_at: Date,
    ) -> FileResults:
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except for error handling. The scanner
        always returns results (see return value below) regardless of whether
        the scan completed successfully or raised an exception.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        Returns:
            Scanner results (event metadata, extracted files, discovered IOCs)
            stored in a `FileResults` object.
        Raises:
            DistributionTimeout: raised when distribution times out
            RequestTimeout: raised when request times out
            Exception: Unknown exception occurred.
        """
        start = time.time()
        self.event = {}
        self.file = file
        self.options = options
        self.expire_at = expire_at

        try:
            with (
                self.start_span("scan", attributes=self),
                timeout_after(self.scanner_timeout, ScannerTimeout),
            ):
                result = self.scan(data, file, options, expire_at)

        except ScannerTimeout:
            self.add_flag("timed_out", None)

        except ScannerException:
            self.add_exception()

        except Exception:
            logging.exception(
                "%s: unhandled exception while scanning %s",
                self.name,
                file.tree.node,
            )
            self.add_flag("uncaught_exception")

        else:
            if isinstance(result, dict):
                self.event.update(result)
            elif isinstance(result, BaseModel):
                self.event.update(result.model_dump(exclude_unset=True))
            elif dataclasses.is_dataclass(result):
                self.event.update(dataclass_to_dict(result))
            elif result is not None:
                logging.warning("discarding scanner return value: %r", result)
                self.add_flag("discarded_scanner_return")

        return FileResults(
            file=file,
            scan={
                self.key: ScannerResults(
                    scanner=self.key,
                    elapsed=round(time.time() - start, 6),
                    **self.event,
                ),
            },
            children=self.children,
            exceptions=self.exceptions,
            flags=set(map(self._format_flag, self.flags)),
            related=self.related,
            rules=self.rules,
        )

    def emit_file(
        self,
        data: bytes | bytearray | memoryview[int] | None,
        *,
        flavors: Iterable[str] = (),
        mime_type: Iterable[str] = (),
        unique_key: Iterable[Hashable] = (),
        hash: Hash | None = None,
        type: str = FileType.file,
        **kwargs,
    ) -> uuid.UUID | None:
        """Re-ingest extracted file"""

        # either we were given some combination of deterministic keys (e.g. position in
        # file/stream, filename, etc.), or we rely upon the order the scanner generates
        # children to be deterministic; if neither of these are true, scanning will
        # still -work-, but UUIDs won't be deterministic, which won't allow for
        # reproducible scanner runs
        unique_key = (
            self.name,
            kwargs.get("path", kwargs.get("name")),
            (*unique_key,) or (self.emitted_files,),
        )
        # make sure that our unique key is actually unique
        if unique_key in self.__child_keys:
            raise ValueError(f"child with key {unique_key!r} already exists")

        if data is not None:
            # convert to bytes to allow for tasting, etc. and set length if not given
            data = bytes(data)
            kwargs.setdefault("size", len(data))

            # calculate hashes/mimetype/etc. for our data
            hash = hash or Hash.for_data(data)
            tasted_mime = self.backend.taste_mime(data)
        else:
            tasted_mime = ()

        # create a new child based on the currently processing file
        child = self.file.child(
            unique_key,
            has_data=(data is not None),
            flavors={
                "external": flavors,
            },
            source=self.key,
            hash=hash,
            type=type,
            mime_type={
                *mime_type,
                *tasted_mime,
            },
            **kwargs,
        )

        if data is not None:
            try:
                # we have to call to the backend to handle setting file data in order to
                # give database-backed backends a chance to push the data into the database
                # instead of storing it locally
                self.backend.store_file_data(child, data, self.expire_at)
            except Exception:
                logging.exception("failed to emit file")
                self.add_flag(f"failed_to_emit_file:{child.tree.node}")
                return None

        # we successfully attached data to the file, so add it to our known children
        # and set of unique keys we've seen
        self.children.append(child)
        self.__child_keys.add(unique_key)
        return child.tree.node

    @property
    def emitted_files(self) -> int:
        return len(self.children)

    def _format_flag(self, flag: str) -> str:
        return f"{self.key}:{flag}"

    def add_flag(
        self,
        flag: str,
        exception: BaseException | None | EllipsisType = ...,
    ) -> None:
        self.flags.add(flag)
        if exception is ...:
            exception = sys.exception()
        if exception is not None:
            self.exceptions.add(
                ExceptionInfo(
                    exception=exception,
                    scanner=self.key,
                    flag=self._format_flag(flag),
                )
            )

    def add_exception(
        self,
        exception: BaseException | None | EllipsisType = ...,
    ) -> None:
        if exception is ...:
            exception = sys.exception()
        if exception is not None:
            self.exceptions.add(
                ExceptionInfo(
                    exception=exception,
                    scanner=self.key,
                )
            )

    def _parse_indicator(self, what: Any, type: str | None = None) -> Iterator[Indicator]:
        try:
            yield from Indicator.parse(what, self, type=type)
        except:
            logging.exception("failed to parse indicator: %r", what)

    @deprecated("Use Scanner.add_related() or Scanner.add_rule_match() instead.")
    def add_iocs(self, values: Iterable[Any], /, *, type: str | None = None) -> None:
        """
        Processes any number of indicators of compromise (IOCs) and adds them to
        the scanner's set of IOCs.

        This method takes any number of IOCs (such as URLs, domains, IP
        addresses, or emails), categorizes them using validators and regexes,
        then adds a match to the scanner's set of IOCs. If the IOC does not
        match any valid type, a warning is logged, and the IOC is not added.

        Args:
            values (Any): The IOC(s) to be processed.

        Note:
            - IOCs may be provided as bytes objects, in which case they are
              decoded into strings before processing.
            - The method internally handles different formats and types of IOCs
              (like URLs, domains, IPs, and emails).
            - If the IOC is invalid or does not match a known pattern, a warning
              is logged and the IOC is not added.
        """
        for value in values:
            if isinstance(value, bytes):
                value = value.decode()
            self.rules.append(
                Rule.model_validate(
                    {
                        "scanner": self,
                        "matched": self._parse_indicator(value, type=type),
                    }
                )
            )

    def add_related(self, values: Iterable[Any], /, type: str | None = None) -> None:
        for value in values:
            # add any indicators to our set directly, since we don't need to do
            # anything to them beforehand
            if isinstance(value, Indicator):
                self.related.add(value)
            # if it's not an indicator, try to parse it and store any results
            else:
                if isinstance(value, bytes):
                    value = value.decode()
                self.related.update(self._parse_indicator(value, type=type))

    @overload
    def add_rule_match(
        self,
        rule_object: Rule,
        /,
    ) -> None: ...

    @overload
    def add_rule_match(
        self,
        rule_object: Literal[None] = None,
        /,
        *,
        name: str | None = None,
        author: Iterable[str] | str | None = None,
        category: str | None = None,
        description: str | None = None,
        id: Any | None = None,
        license: str | None = None,
        provider: str | None = None,
        reference: str | None = None,
        ruleset: str | None = None,
        uuid: Any | None = None,
        version: str | None = None,
        matched: Iterable[Any] = (),
    ) -> None: ...

    def add_rule_match(
        self,
        rule_object: Rule | None = None,
        /,
        *,
        name: str | None = None,
        author: Iterable[str] | str | None = None,
        category: str | None = None,
        description: str | None = None,
        id: Any | None = None,
        license: str | None = None,
        provider: str | None = None,
        reference: str | None = None,
        ruleset: str | None = None,
        uuid: Any | None = None,
        version: str | None = None,
        matched: Iterable[Any] = (),
    ) -> None:
        if not rule_object:
            kwargs = dict(
                filter_mapping(
                    None,
                    {
                        "scanner": self,
                        "name": name,
                        "author": author,
                        "category": category,
                        "description": description,
                        "id": id,
                        "license": license,
                        "provider": provider,
                        "reference": reference,
                        "ruleset": ruleset,
                        "uuid": uuid,
                        "version": version,
                        "matched": set(itertools.chain(
                            *(self._parse_indicator(m) for m in matched)
                        )),
                    },
                )
            )
            if kwargs:
                self.rules.append(Rule.model_validate(kwargs))
        else:
            assert rule_object.scanner == self.key
            self.rules.append(rule_object)
