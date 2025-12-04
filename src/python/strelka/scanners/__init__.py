from __future__ import annotations
from abc import ABCMeta, abstractmethod
import contextlib
import dataclasses
import datetime
import itertools
import logging
import math
from os import PathLike
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
from types import EllipsisType
from typing import (
    Any,
    ClassVar,
    Hashable,
    IO,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    NoReturn,
    TYPE_CHECKING,
    overload,
)
import uuid

import inflection
from opentelemetry import trace
from pydantic import BaseModel
from typing_extensions import deprecated

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
    Technique,
)
from ..telemetry.traces import SpanCreatorMixin
from ..util import ensure_string
from ..util.collections import ListCompatibleSet, dataclass_to_dict, filter_mapping
from ..util.files import find_executable
from ..util.timeout import BaseTimeout, timeout_after

if TYPE_CHECKING:
    from _typeshed import DataclassInstance
else:
    DataclassInstance = "_typeshed.DataclassInstance"


Options = Mapping[str, Any]
Expiration = float
UniqueKey = tuple[Hashable, ...]


class _ScannerFatalError(BaseException):
    pass


class ScannerCalledProcessError(subprocess.CalledProcessError):
    _include_stderr_in_str: bool

    def __init__(
        self,
        returncode: int,
        cmd: subprocess._CMD,
        output: str | bytes | None = None,
        stderr: str | bytes | None = None,
        include_stderr_in_str: bool = True,
    ) -> None:
        super().__init__(returncode, cmd, output, stderr)
        self._include_stderr_in_str = include_stderr_in_str

    def __str__(self) -> str:
        if self._include_stderr_in_str and self.stderr:
            return "Command {!r} exited with failure status {}; STDERR:\n{}".format(
                self.cmd,
                self.returncode,
                textwrap.indent(self.stderr, "  > "),
            )
        else:
            return "Command {!r} exited with failure status {}.".format(
                self.cmd,
                self.returncode,
            )


class ScannerUtilMethods:
    @overload
    @classmethod
    def evaluate_limit(cls, value: int) -> int: ...

    @overload
    @classmethod
    def evaluate_limit(cls, value: float) -> float: ...

    @classmethod
    def evaluate_limit(cls, value: int | float) -> int | float:
        if isinstance(value, int):
            if value < 0:
                return sys.maxsize
            return value
        else:
            if value < 0:
                return math.inf
            return value

    @classmethod
    def normalize_key(cls, key: str, words: set[str] | None = None) -> str:
        for word in words or ():
            key = key.replace(word, word.title())
        return inflection.underscore(
            key.replace(" ", "_").replace("/", "_").replace(".", "_")
        )

    @classmethod
    def find_executable(
        cls,
        program: str | bytes | PathLike | None,
        path: str | bytes | PathLike | None = None,
    ) -> str | None:
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
    def tmp_directory(self) -> str:
        return self.options.get("tmp_directory", tempfile.gettempdir())

    def run_program(
        self,
        program: str | bytes | PathLike,
        args: Iterable[Any] = (),
        /,
        *,
        program_path: str | bytes | PathLike | None = None,
        input: str | IO[bytes] | IO[str] | None = None,
        output: (
            Literal["capture", "drop"]
            | None
            | subprocess._FILE
            | tuple[IO[bytes] | IO[str], IO[bytes] | IO[str]]
        ) = "capture",
        shell: bool = False,
        cwd: None | str | bytes | PathLike = None,
        timeout: float | None = None,
        check: bool = False,
        valid_returncodes: Iterable[int] = (0,),
        encoding: str | None = None,
        errors: str | None = None,
        text: bool | None = None,
        env: Mapping[Any, Any] | None = None,
        include_stderr_in_exception: bool = True,
        **popen_kwargs,
    ) -> subprocess.CompletedProcess:
        program_path = self.find_executable(program, program_path)
        if program_path is None:
            raise FileNotFoundError(f"unable to locate program: {program}")

        def _expand_arg(arg: Any) -> Iterator[str]:
            if arg is None:
                return
            if isinstance(arg, tuple):
                for a in arg:
                    yield from _expand_arg(a)
            elif isinstance(arg, os.PathLike):
                yield str(Path(os.fspath(arg)).expanduser())
            else:
                yield ensure_string(arg)

        args = [program_path, *itertools.chain(*map(_expand_arg, args))]
        stdin = None
        stdout = None
        stderr = None

        if input is not None and not isinstance(input, (str, bytes)):
            stdin, input = input, None

        if output == "capture":
            stdout = stderr = subprocess.PIPE
        elif output == "drop":
            stdout = stderr = subprocess.DEVNULL
        elif isinstance(output, IO):
            stdout = output
        elif isinstance(output, tuple):
            stdout, stderr = output
        else:
            stdout = output

        if cwd is not None:
            cwd = ensure_string(cwd)
        if env is not None:
            env = {ensure_string(k): ensure_string(v) for k, v in env.items()}

        process = subprocess.Popen(
            args,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            shell=shell,
            encoding=encoding,
            errors=errors,
            text=text,
            **popen_kwargs,
        )
        try:
            out, err = process.communicate(input, timeout)
        except BaseTimeout:
            process.kill()
            process.wait()
            self.add_flag("subprocess_killed", None)
            raise
        except subprocess.TimeoutExpired:
            self.add_flag("subprocess_timed_out", None)
            process.kill()
            process.wait()
            self.add_flag("subprocess_killed", None)
            raise
        else:
            rc = process.returncode
            if check and rc not in set(valid_returncodes):
                raise ScannerCalledProcessError(
                    rc, args, out, err, include_stderr_in_exception
                )
            return subprocess.CompletedProcess(args, rc, out, err)

    @overload
    @contextlib.contextmanager
    def new_temporary_file(
        self,
        data: None = None,
        *,
        encoding: None = None,
        buffering: int = -1,
        named: bool = False,
        spooled: bool = False,
        **kwargs,
    ) -> Iterator[IO[bytes]]: ...

    @overload
    @contextlib.contextmanager
    def new_temporary_file(
        self,
        data: None = None,
        *,
        encoding: str,
        errors: str | None = None,
        buffering: int = -1,
        chunk_size: int = 102400,
        named: bool = False,
        spooled: bool = False,
        **kwargs,
    ) -> Iterator[IO[str]]: ...

    @overload
    @contextlib.contextmanager
    def new_temporary_file(
        self,
        data: bytes | IO[bytes],
        *,
        encoding: None = None,
        buffering: int = -1,
        chunk_size: int = 102400,
        named: bool = False,
        spooled: bool = False,
        **kwargs,
    ) -> Iterator[IO[bytes]]: ...

    @overload
    @contextlib.contextmanager
    def new_temporary_file(
        self,
        data: str | IO[str],
        *,
        encoding: str,
        errors: str | None = None,
        buffering: int = -1,
        chunk_size: int = 102400,
        named: bool = False,
        spooled: bool = False,
        **kwargs,
    ) -> Iterator[IO[str]]: ...

    @contextlib.contextmanager
    def new_temporary_file(
        self,
        data: str | bytes | IO[str] | IO[bytes] | None = None,
        *,
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        chunk_size: int = 102400,
        named: bool = False,
        spooled: bool = False,
        **kwargs,
    ) -> Iterator[IO[str] | IO[bytes]]:
        if named:
            handle_cls = tempfile.NamedTemporaryFile
        elif spooled:
            handle_cls = tempfile.SpooledTemporaryFile
        else:
            handle_cls = tempfile.TemporaryFile

        with handle_cls(
            mode=("w+" if encoding is not None else "w+b"),
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            dir=self.tmp_directory,
            **kwargs,
        ) as handle:
            if isinstance(data, (str, bytes)):
                handle.write(data)
            elif isinstance(data, IO):
                while d := data.read(chunk_size):
                    handle.write(d)
            handle.flush()
            handle.seek(0, os.SEEK_SET)
            yield handle

    @contextlib.contextmanager
    def new_temporary_dir(
        self,
        **kwargs,
    ) -> Iterator[Path]:
        with tempfile.TemporaryDirectory(
            dir=self.tmp_directory,
            **kwargs,
        ) as handle:
            yield Path(handle)

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
        self.options = self.backend.config.options_for_scanner(self.name, options)
        self.expire_at = expire_at

        try:
            with (
                self.start_span("scan", attributes=self),
                timeout_after(self.scanner_timeout, ScannerTimeout),
            ):
                result = self.scan(data, file, options, expire_at)

        except ScannerTimeout:
            self.add_flag("timed_out", None)

        except _ScannerFatalError:
            pass

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
        msg: str | None = None,
    ) -> None:
        self.flags.add(flag)
        if msg is not None:
            exception = RuntimeError(msg)
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

    def fail(
        self,
        flag: str,
        exception: BaseException | None | EllipsisType = ...,
        msg: str | None = None,
    ) -> NoReturn:
        self.add_flag(flag, exception, msg)
        raise _ScannerFatalError()

    def add_exception(
        self,
        exception: BaseException | None | EllipsisType = ...,
        msg: str | None = None,
    ) -> None:
        if msg is not None:
            exception = RuntimeError(msg)
        if exception is ...:
            exception = sys.exception()
        if exception is not None:
            self.exceptions.add(
                ExceptionInfo(
                    exception=exception,
                    scanner=self.key,
                )
            )

    def _parse_indicator(
        self, what: Any, type: str | None = None
    ) -> Iterator[Indicator]:
        try:
            yield from Indicator.parse(what, self, type=type)
        except Exception:
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
        reference: Iterable[str] | str | None = None,
        ruleset: str | None = None,
        uuid: Any | None = None,
        version: str | None = None,
        matched: Iterable[Any] = (),
        tags: Iterable[str] = (),
        techniques: Iterable[Technique] = (),
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
        reference: Iterable[str] | str | None = None,
        ruleset: str | None = None,
        uuid: Any | None = None,
        version: str | None = None,
        matched: Iterable[Any] = (),
        tags: Iterable[str] = (),
        techniques: Iterable[Technique] = (),
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
                        "matched": set(
                            itertools.chain(
                                *(self._parse_indicator(m) for m in matched)
                            )
                        ),
                        "tags": set(tags),
                        "techniques": set(techniques),
                    },
                )
            )
            if kwargs:
                self.rules.append(Rule.model_validate(kwargs))
        else:
            assert rule_object.scanner == self.key
            self.rules.append(rule_object)
