from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import enum
import pathlib
import typing

DEFAULT_CHUNKSIZE: typing.Final[int]


class XarError(Exception):
    pass


class XarFileType(enum.Enum):
    REG = "file"
    DIR = "directory"
    SYM = "symlink"
    LNK = "hardlink"
    FIFO = "fifo"
    CHR = "character special"
    BLK = "block special"
    SOCK = "socket"
    WHT = "whiteout"
    # these aren't standard values, but helpers
    ORIG = "(original)"
    OTHER = "(other)"
    MISSING = "(missing)"


class _XarFilePointer:
    archive: XarArchive

    def __init__(self, archive: XarArchive, pointer) -> None: ...
    def invalidate(self) -> None: ...
    @property
    def valid(self) -> bool: ...


@dataclass(frozen=True, repr=False)
class XarInfo:
    pointer: _XarFilePointer
    name: str
    size: int
    mtime: datetime | None
    mode: int | None
    type: XarFileType
    type_string: str | None
    linkname: str | None
    uid: int | None
    gid: int | None
    uname: str | None
    gname: str | None
    devmajor: int | None
    devminor: int | None

    def isfile(self) -> bool: ...
    def isreg(self) -> bool: ...
    def isdir(self) -> bool: ...
    def issym(self) -> bool: ...
    def islnk(self) -> bool: ...
    def ischr(self) -> bool: ...
    def isblk(self) -> bool: ...
    def isfifo(self) -> bool: ...
    def issock(self) -> bool: ...
    def iswht(self) -> bool: ...
    def isdev(self) -> bool: ...
    def filemode(self) -> str: ...
    @property
    def current(self) -> bool: ...
    def get_blocks(self, size: int = DEFAULT_CHUNKSIZE) -> typing.Iterator[bytes]: ...


class _XarIterator:
    pass


class XarInfoIterator(_XarIterator):
    archive: XarArchive
    entry: object

    def __init__(self, archive: XarArchive) -> None: ...
    def __next__(self) -> XarInfo: ...


class XarArchive:
    path: object

    def __init__(self, path: str | pathlib.Path) -> None: ...
    def __iter__(self) -> XarInfoIterator: ...
    def close(self) -> None: ...
    @property
    def closed(self) -> bool: ...
    def __enter__(self) -> typing.Self: ...
    def __exit__(self, a, b, c) -> None: ...
