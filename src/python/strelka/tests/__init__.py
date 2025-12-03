import base64
import binascii
import builtins
from datetime import UTC, datetime, timedelta
import hashlib
import importlib
from pathlib import Path
from types import EllipsisType
from typing import (
    Any,
    Callable,
    ClassVar,
    Final,
    Iterable,
    Literal,
    Mapping,
    cast,
    overload,
)
from unittest import TestCase, mock
from uuid import UUID

import inflection
import pytest

from ..backend import BaseBackend
from ..model import File, NULL_UUID, Tree
from ..model import serialize
from ..scanners import FileResults, Options, Scanner
from ..util import MISSING, _MISSING
from ..util.collections import filter_mapping, merge, visit


ExceptionCondition = type[BaseException] | tuple[type[BaseException], ...]


EMPTY_EVENT: Final = {
    "files": [],
    "related": [],
    "rules": [],
    "flags": [],
    "exceptions": [],
    "scan": {
        "elapsed": ...,
        "scanner": ...,
    },
}


EMPTY_CHILD: Final = {
    "tree": {
        "root": str(NULL_UUID),
        "node": ...,
        "parent": str(NULL_UUID),
        "depth": 1,
    },
    "source": ...,
    "metadata": ...,
    "flavors": ...,
    "accessed": ...,
    "attributes": ...,
    "created": ...,
    "ctime": ...,
    "device": ...,
    "directory": ...,
    "drive_letter": ...,
    "extension": ...,
    "fork_name": ...,
    "gid": ...,
    "group": ...,
    "inode": ...,
    "mime_type": ...,
    "mode": ...,
    "mtime": ...,
    "name": ...,
    "origin_referrer_url": ...,
    "origin_url": ...,
    "owner": ...,
    "path": ...,
    "size": ...,
    "target_path": ...,
    "uid": ...,
    "hash": {
        "cdhash": ...,
        "md5": ...,
        "sha1": ...,
        "sha256": ...,
        "sha384": ...,
        "sha512": ...,
        "ssdeep": ...,
        "tlsh": ...,
    },
}


MockAny = EllipsisType


def make_child(
    uuid: str | UUID,
    *,
    path: str | MockAny = ...,
    extension: str | MockAny = ...,
    name: str | MockAny = ...,
    directory: str | MockAny = ...,
    fork_name: str | MockAny = ...,
    source: str | Scanner | type[Scanner] | MockAny = ...,
    flavors: Mapping[str, Iterable[str]] | Iterable[str] | MockAny = ...,
    mime_type: Iterable[str] = (),
    size: int | MockAny = ...,
    md5: str | MockAny = ...,
    sha1: str | MockAny = ...,
    sha256: str | MockAny = ...,
    sha384: str | MockAny = ...,
    sha512: str | MockAny = ...,
    type: str = "file",
    **kwargs,
) -> dict[str, Any]:
    if isinstance(source, Scanner) or isinstance(source, builtins.type):
        source = source.key

    if isinstance(flavors, Mapping):
        flavors = {k: set(v) for k, v in flavors.items()}
    elif isinstance(flavors, Iterable):
        flavors = {"external": set(flavors)}

    hash = {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha384": sha384,
        "sha512": sha512,
        "ssdeep": ...,
        "tlsh": ...,
    }
    if all(v is ... for v in hash.values()):
        hash = ...

    if path is not ...:
        sep = "\\" if "\\" in path else "/"
        *_, p, n = ..., *path.rsplit(sep, 1)
        n, f, *_ = *n.split(":", 1), ...
        if name is ...:
            if n and n is not ...:
                name = n
            elif path == sep:
                name = sep
        if directory is ...:
            if p and p is not ...:
                directory = p
            elif path == sep:
                directory = sep
        if f and f is not ... and fork_name is ...:
            fork_name = f

    elif directory is not ... and name is not ...:
        sep = "\\" if "\\" in directory else "/"
        path = sep.join([directory, name])

    if name is not ...:
        if extension is ...:
            *_, n, e = None, *name.rsplit(".", 1)
            if n and e:
                extension = e

    return {
        "tree": {
            "root": str(NULL_UUID),
            "node": str(uuid),
            "parent": str(NULL_UUID),
            "depth": 1,
        },
        "mime_type": {*mime_type},
        "hash": hash,
        "flavors": flavors,
        "source": source,
        "type": type,
        **{
            k: v
            for k, v in [
                ("name", name),
                ("path", path),
                ("extension", extension),
                ("directory", directory),
                ("fork_name", fork_name),
                ("size", size),
            ]
            if v is not ...
        },
        **kwargs,
    }


def make_rule(**kwargs) -> dict:
    return {
        "scanner": ...,
        **kwargs,
    }


def make_indicator(
    type: str,
    value: Any,
) -> dict:
    return {
        "type": type,
        "value": value,
        "scanner": ...,
    }


def make_exception(
    qualified_name: str,
    message: str,
    flag: str | None = None,
    name: str | None = None,
) -> dict:
    return dict(
        filter_mapping(
            None,
            {
                "timestamp": ...,
                "scanner": ...,
                "qualified_name": qualified_name,
                "name": name or qualified_name.rsplit(".", 1)[-1],
                "message": message,
                "traceback": ...,
                "flag": flag,
            },
        )
    )


@overload
def make_event(
    *,
    files: Iterable[dict] | None = None,
    related: Iterable[dict] | None = None,
    rules: Iterable[dict] | None = None,
    scan: dict | None = None,
    flags: Iterable[str] | None = None,
    exceptions: Iterable[dict] | None = None,
) -> dict: ...


@overload
def make_event(contents: dict | None = None) -> dict: ...


def make_event(
    contents: dict | None = None,
    *,
    files: Iterable[dict] | None = None,
    related: Iterable[dict] | None = None,
    rules: Iterable[dict] | None = None,
    scan: dict | None = None,
    flags: Iterable[str] | None = None,
    exceptions: Iterable[dict] | None = None,
) -> dict:
    if not contents:
        contents = {"scan": {}}
    if files:
        contents["files"] = list(files)
    if related:
        contents["related"] = list(related)
    if rules:
        contents["rules"] = list(rules)
    if scan:
        contents["scan"].update(scan)
    if exceptions:
        contents["exceptions"] = list(exceptions)
        if exc_flags := {f for e in contents["exceptions"] if (f := e.get("flag"))}:
            flags = set(flags or ())
            flags.update(exc_flags)
    if flags:
        contents["flags"] = set(flags)

    return dict(
        visit(
            merge(EMPTY_EVENT, contents),
            lambda e, _: mock.ANY if e is ... else e,
        )
    )


def parse_timestamp(ts: str) -> str:
    return serialize(datetime.fromisoformat(ts), as_json=False)


DEFAULT_SCANNER_OPTIONS: Final = {
    "scanner_timeout": 30,
}

DEFAULT_BACKEND_CONFIG: Final = {
    "limits": {
        "scanner": 30,
    },
}

tests_dir: Final = Path(__file__).parent


@overload
def run_test_scan(
    *,
    scanner: Scanner,
    fixture: File,
    options: Options | _MISSING = MISSING,
    expire_at: datetime | None = None,
    expected: dict | None = None,
    checks: Iterable[Callable[[dict], bool] | Callable[[dict], None]] = (),
) -> dict: ...


@overload
def run_test_scan(
    *,
    scanner: Scanner,
    fixture: File,
    raises: ExceptionCondition,
    options: Options | _MISSING = MISSING,
    expire_at: datetime | None = None,
) -> None: ...


@overload
def run_test_scan(
    *,
    scan_class: type[Scanner],
    backend: BaseBackend,
    fixture: File,
    options: Options | _MISSING = MISSING,
    expire_at: datetime | None = None,
    expected: dict | None = None,
    checks: Iterable[Callable[[dict], bool] | Callable[[dict], None]] = (),
) -> dict: ...


@overload
def run_test_scan(
    *,
    scan_class: type[Scanner],
    backend: BaseBackend,
    fixture: File,
    raises: ExceptionCondition,
    options: Options | _MISSING = MISSING,
    expire_at: datetime | None = None,
) -> None: ...


def run_test_scan(
    *,
    fixture: File,
    scanner: Scanner | None = None,
    scan_class: type[Scanner] | None = None,
    backend: BaseBackend | None = None,
    options: Options | _MISSING = MISSING,
    expire_at: datetime | None = None,
    expected: dict | None = None,
    raises: ExceptionCondition | None = None,
    checks: Iterable[Callable[[dict], bool] | Callable[[dict], None]] = (),
) -> dict | None:
    # ensure we have an expiration timestamp; pick something reasonable if we
    # weren't given one to use
    if expire_at is None:
        expire_at = datetime.now(UTC) + timedelta(hours=1)
    expire_at = expire_at.astimezone(UTC)

    if scanner is None:
        if scan_class is None or backend is None:
            pytest.fail(
                "run_test_scan() requires either a scanner instance or a "
                "scanner class and a backend instance",
            )
        scanner = scan_class(backend)
    else:
        backend = scanner.backend

    # build our scanner options by combining our hard-coded default scanner
    # options, any testing-specific scanner options that were provided in the
    # backend configuration file, and any options provided as an argument
    options = merge(
        DEFAULT_SCANNER_OPTIONS,
        backend.config.options_for_scanner(
            scanner.name,
            backend.config.get(f"testing.options.{scanner.name}", {}),
            options,
        ),
    )

    # get our file data from the backend
    data = backend.retrieve_file_data(fixture) or b""

    def perform_scan() -> FileResults:
        return scanner.scan_wrapper(
            data=data,
            file=fixture,
            options=options,
            expire_at=expire_at,
        )

    # if we were given an exception to make sure is raised, use the
    # .assertRaises() method to handle checking; also ensure we weren't given
    # anything to look for in the results, since there are none
    if raises is not None:
        TestCase().assertRaises(raises, perform_scan)
        TestCase().assertIs(expected, None)
        TestCase().assertFalse(bool(checks))
        test_results = None

    # otherwise, just perform the scan and transform the results
    else:
        scan_results = perform_scan()
        this_scan = scan_results.scan.get(scanner.key)
        assert this_scan is not None

        test_results = serialize(
            {
                # include any indicators that the scanner reported
                "related": scan_results.related,
                "rules": scan_results.rules,
                # also include the UIDs/hashes of any files created, so we can
                # validate that the extracted data is what we want
                "files": scan_results.children,
                # also include flags/exceptions
                "flags": scan_results.flags,
                "exceptions": scan_results.exceptions,
                # and finally include the actual scan event contents
                "scan": this_scan,
            },
            convert_bytes=False,
            as_json=False,
        )
        # if we were given something to compare to, perform the comparison
        if expected is not None:
            TestCase().assertDictEqual(expected, test_results)
        for check in checks:
            TestCase().assertIn(check(cast(dict, test_results)), {None, True})

    return test_results


def scanner_class_fixture(key: str) -> Callable[..., type[Scanner]]:
    @pytest.fixture
    def _scanner_class_fixture(*, _key=key) -> type[Scanner]:
        return get_scanner_class(_key)

    return _scanner_class_fixture


def scanner_fixture(key: str) -> Callable[..., Scanner]:
    @pytest.fixture
    def _scanner_fixture(backend: BaseBackend, *, _key=key) -> Scanner:
        return get_scanner_class(_key)(backend)

    return _scanner_fixture


FileFixtureEncoding = Literal["bytes", "str", "base64", "hex"]


@overload
def local_fixture(
    name: str,
    *,
    encoding: None = None,
    root: UUID = NULL_UUID,
) -> Callable[..., File]: ...


@overload
def local_fixture(
    name: str,
    *,
    encoding: Literal["str", "base64", "hex"],
    root: UUID = NULL_UUID,
) -> Callable[..., str]: ...


@overload
def local_fixture(
    name: str,
    *,
    encoding: Literal["bytes"],
    root: UUID = NULL_UUID,
) -> Callable[..., bytes]: ...


def local_fixture(
    name: Path | str,
    *,
    encoding: FileFixtureEncoding | None = None,
    root: UUID = NULL_UUID,
) -> Callable[..., File | str | bytes]:
    @pytest.fixture
    def _local_fixture(
        backend: BaseBackend,
        *,
        _name: str | Path = name,
        _enc: FileFixtureEncoding | None = encoding,
        _root: UUID = root,
    ) -> File | str | bytes:
        return get_local_fixture(
            backend,
            Path(_name),
            encoding=_enc,
            root=_root,
        )

    return _local_fixture


def hash_file(data: bytes | None) -> str | None:
    if data is not None:
        return hashlib.sha256(data).hexdigest()
    return None


def get_scanner_class(key: str) -> type[Scanner]:
    module = importlib.import_module(f"strelka.scanners.scan_{key}")
    return getattr(module, inflection.camelize(f"scan_{key}"))


class ScannerFixtureFactory:
    def __getattr__(self, scanner: str) -> Callable[..., Scanner]:
        return scanner_fixture(scanner)


class LocalFileFixtureFactory:
    __root: Path

    def __init__(self, root: str | Path) -> None:
        self.__root = Path(root)

    @overload
    def __call__(
        self,
        path: str | Path,
        *,
        encoding: None = None,
    ) -> Callable[..., File]: ...

    @overload
    def __call__(
        self,
        path: str | Path,
        *,
        encoding: Literal["str", "base64", "hex"],
    ) -> Callable[..., str]: ...

    @overload
    def __call__(
        self,
        path: str | Path,
        *,
        encoding: Literal["bytes"],
    ) -> Callable[..., str]: ...

    def __call__(
        self,
        path: str | Path,
        *,
        encoding: FileFixtureEncoding | None = None,
        root: UUID = NULL_UUID,
    ) -> Callable[..., File | str | bytes]:
        return local_fixture(
            str(self.__root / path),
            encoding=encoding,
            root=root,
        )


class fixtures:
    scanners: ClassVar = ScannerFixtureFactory()
    data: ClassVar = LocalFileFixtureFactory("fixtures")
    helpers: ClassVar = LocalFileFixtureFactory("helpers")
    results: ClassVar = LocalFileFixtureFactory("results")


@overload
def get_local_fixture(
    backend: BaseBackend,
    what: Path,
    *,
    encoding: None = None,
    root: UUID = NULL_UUID,
) -> File: ...


@overload
def get_local_fixture(
    backend: BaseBackend,
    what: Path,
    *,
    encoding: Literal["str", "base64", "hex"],
    root: UUID = NULL_UUID,
) -> str: ...


@overload
def get_local_fixture(
    backend: BaseBackend,
    what: Path,
    *,
    encoding: Literal["bytes"],
    root: UUID = NULL_UUID,
) -> bytes: ...


def get_local_fixture(
    backend: BaseBackend,
    what: Path,
    *,
    encoding: FileFixtureEncoding | None = None,
    root: UUID = NULL_UUID,
) -> File | str | bytes:
    path = tests_dir / Path(what)
    data = path.read_bytes()

    match encoding:
        case "bytes":
            return data
        case "str":
            return data.decode()
        case "base64":
            return base64.b64encode(data).decode()
        case "hex":
            return binascii.hexlify(data).decode()
        case _:
            file = File(
                has_data=True,
                path=str(path),
                name=path.name,
                tree=Tree(root=root),
            )
            backend.store_file_data(file, data, datetime.now(UTC) + timedelta(hours=1))
            return file


# def get_remote_fixture(url: str, session: requests.Session | None = None) -> io.BytesIO:
#     """Download a fixture from a URL"""
#
#     # Get a streamed version of the downloaded file
#     response = (session or requests).get(url, stream=True)
#     response.raw.decode_content = True
#
#     # Convert the raw file-like object to a real BytesIO object
#     bytesfile = io.BytesIO()
#     bytesfile.write(response.raw.read())
#     bytesfile.seek(0)
#
#     return bytesfile
#
#
# def extract_archive(
#     bytesfile: IO[bytes],
#     path: str = "fixture",
#     password: str | None = None,
# ) -> dict[str, IO[bytes] | None]:
#     """Decompress zip, 7zip, gzip, tar+gzip remote fixtures with an optional password"""
#
#     base = os.path.basename(path)
#     mime = magic.Magic(mime=True)
#     data = bytesfile.read()
#     mime_type = mime.from_buffer(data)
#     buffer = io.BytesIO(data)
#     allfiles = {}
#
#     if mime_type == "application/zip":
#         zip_password = password.encode("utf-8") if password else None
#         with ZipFile(buffer) as archive:
#             for entry in archive.filelist:
#                 if not entry.is_dir():
#                     allfiles[entry.filename] = io.BytesIO(
#                         archive.read(entry.filename, pwd=zip_password)
#                     )
#
#     elif mime_type == "application/x-7z-compressed":
#         with py7zr.SevenZipFile(buffer, password=password) as archive:
#             allfiles.update(archive.readall() or {})
#
#     elif mime_type == "application/x-bzip2":
#         if base.endswith(".tbz2"):
#             base = base.removesuffix(".tbz2") + ".tar"
#         elif base.endswith(".bz2"):
#             base = base.removesuffix(".bz2")
#         with bz2.open(buffer) as archive:
#             return extract_archive(archive, base)
#
#     elif mime_type == "application/gzip":
#         if base.endswith(".tgz"):
#             base = base.removesuffix(".tgz") + ".tar"
#         elif base.endswith(".gz"):
#             base = base.removesuffix(".gz")
#         with gzip.open(buffer) as archive:
#             return extract_archive(cast(IO[bytes], archive), base)
#
#     elif mime_type == "application/x-tar":
#         with tarfile.open(fileobj=buffer) as archive:
#             for member in archive.getmembers():
#                 if member.isfile():
#                     fh = archive.extractfile(member)
#                     data = io.BytesIO(fh.read()) if fh else None
#                     allfiles[member.name] = data
#
#     else:
#         logging.warning(
#             "unsure how to treat file of type %s as an archive",
#             mime_type,
#         )
#         allfiles[base] = buffer
#
#     return allfiles
