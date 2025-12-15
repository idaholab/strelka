# cython: language_level=3

cimport _libxar
from cpython.pycapsule cimport PyCapsule_New, PyCapsule_IsValid, PyCapsule_GetPointer
from cpython.bytes cimport PyBytes_FromString, PyBytes_FromStringAndSize
cimport cpython.array
from cython cimport view
from libc.stdint cimport intptr_t
from libc.stdlib cimport free
from libc.string cimport memset

import enum
import pathlib
import stat
import typing
from dataclasses import dataclass
from datetime import datetime


DEFAULT_CHUNKSIZE: typing.Final = 1024 * 1024


cdef bytes _make_bytes(char* buffer):
    cdef bytes result
    if buffer == NULL:
        return None
    result = PyBytes_FromString(buffer)
    free(buffer)
    return result


class XarError(Exception):
    pass


class XarFileType(enum.Enum):
    REG     = "file"
    DIR     = "directory"
    SYM     = "symlink"
    LNK     = "hardlink"
    FIFO    = "fifo"
    CHR     = "character special"
    BLK     = "block special"
    SOCK    = "socket"
    WHT     = "whiteout"
    # these aren't standard values, but helpers
    ORIG    = "(original)"
    OTHER   = "(other)"
    MISSING = "(missing)"


cdef class _XarFilePointer:
    cdef readonly XarArchive archive
    cdef _libxar.xar_file_t pointer

    def __cinit__(self) -> None:
        self.archive = None
        self.pointer = NULL

    def __init__(self, XarArchive archive, pointer) -> None:
        self.archive = archive
        if not PyCapsule_IsValid(pointer, b"xar_file_t"):
            raise TypeError("expected capsule of `xar_file_t`")
        self.pointer = PyCapsule_GetPointer(pointer, b"xar_file_t")

    def invalidate(self) -> None:
        self.archive = None
        self.pointer = NULL

    @property
    def valid(self) -> bool:
        return self.pointer != NULL

    def __repr__(self) -> str:
        if self.valid:
            return "<{} #{:x} of {}>".format(
                type(self).__name__,
                <intptr_t>self.pointer,
                self.archive,
            )
        else:
            return "<{} (empty)>".format(
                type(self).__name__,
            )


@dataclass(frozen=True, repr=False)
class XarInfo:
    pointer: _XarFilePointer
    name: str
    size: int = 0
    mtime: datetime | None = None
    mode: int | None = None
    type: XarFileType = XarFileType.MISSING
    type_string: str | None = None
    linkname: str | None = None
    uid: int | None = None
    gid: int | None = None
    uname: str | None = None
    gname: str | None = None
    devmajor: int | None = None
    devminor: int | None = None

    def __repr__(self) -> str:
        return "<{} '{}'{}>".format(
            type(self).__name__,
            self.name,
            self.current and " (current)" or "",
        )

    def isfile(self) -> bool:
        return self.type in {XarFileType.REG, XarFileType.ORIG}

    def isreg(self) -> bool:
        return self.isfile()

    def isdir(self) -> bool:
        return self.type in {XarFileType.DIR}

    def issym(self) -> bool:
        return self.type in {XarFileType.SYM}

    def islnk(self) -> bool:
        return self.type in {XarFileType.LNK, XarFileType.ORIG}

    def ischr(self) -> bool:
        return self.type in {XarFileType.CHR}

    def isblk(self) -> bool:
        return self.type in {XarFileType.BLK}

    def isfifo(self) -> bool:
        return self.type in {XarFileType.FIFO}

    def issock(self) -> bool:
        return self.type in {XarFileType.SOCK}

    def iswht(self) -> bool:
        return self.type in {XarFileType.WHT}

    def isdev(self) -> bool:
        return (self.ischr() or self.isblk() or self.issocket()
                or self.iswht() or self.isfifo())

    def filemode(self) -> str:
        if self.mode is None:
            return "??????????"
        return stat.filemode(self.mode)

    @property
    def current(self) -> bool:
        return self.pointer.valid

    def get_blocks(
        self,
        size: int = DEFAULT_CHUNKSIZE,
    ) -> typing.Iterator[bytes]:
        cdef:
            _libxar.xar_t arc
            _libxar.xar_file_t file
            _libxar.xar_stream stream
            long result
            view.array buffer

        if not self.current:
            raise Exception("cannot extract xar file, not current entry")
        if self.size <= 0:
            return

        arc = (<_XarFilePointer>self.pointer).archive.handle
        file = (<_XarFilePointer>self.pointer).pointer

        result = _libxar.xar_extract_tostream_init(arc, file, &stream)
        if result != _libxar.XAR_STREAM_OK:
            raise Exception("failed to initialize xar extraction stream")
        try:
            buffer = view.array(
                shape = (size,),
                itemsize = sizeof(char),
                format = "b",
            )
            memset(buffer.data, 0, size)
            stream.next_out = <char*>buffer.data
            stream.avail_out = size
            while True:
                result = _libxar.xar_extract_tostream(&stream)
                if result == _libxar.XAR_STREAM_ERR:
                    raise Exception("failed to read data from xar stream")
                if (result == _libxar.XAR_STREAM_END \
                            and stream.avail_out != size) \
                        or stream.avail_out == 0:
                    yield PyBytes_FromStringAndSize(
                        <char*>buffer.data,
                        size - stream.avail_out,
                    )
                    memset(buffer.data, 0, size - stream.avail_out)
                    stream.next_out = <char*>buffer.data
                    stream.avail_out = size
                if result == _libxar.XAR_STREAM_END:
                    break
        finally:
            _libxar.xar_extract_tostream_end(&stream)


cdef class _XarIterator:
    cdef _libxar.xar_iter_t iterator

    def __cinit__(self) -> None:
        self.iterator = _libxar.xar_iter_new()

    def __dealloc__(self) -> None:
        if self.iterator != NULL:
            _libxar.xar_iter_free(self.iterator)
            self.iterator = NULL


cdef class XarInfoIterator(_XarIterator):
    cdef readonly XarArchive archive
    cdef readonly object entry
    cdef _libxar.xar_file_t current
    cdef int index

    def __cinit__(self) -> None:
        self.index = 0
        self.archive = None
        self.entry = None
        self.current = NULL

    def __init__(self, XarArchive archive not None) -> None:
        self.archive = archive

    def __next__(self) -> XarInfo:
        cdef:
            const char* buf
            _libxar.xar_t arc
            _libxar.xar_file_t cur

        arc = self.archive.handle

        if self.index == -1:
            raise StopIteration()
        elif self.index == 0:
            self.current = _libxar.xar_file_first(arc, self.iterator)
        else:
            self.entry.pointer.invalidate()
            self.current = _libxar.xar_file_next(self.iterator)

        if self.current == NULL:
            self.index = -1
            raise StopIteration()

        self.index += 1
        cur = self.current

        # standard properties
        p = {}
        if (path := _make_bytes(_libxar.xar_get_path(cur))) is None:
            raise ValueError("xar file entry has no path?")
        p["name"] = path.decode("utf-8", "backslashreplace")
        if (size := _make_bytes(_libxar.xar_get_size(arc, cur))) is not None:
            p["size"] = int(size)
        if _libxar.xar_prop_get(cur, b"user", &buf) == 0:
            p["uname"] = PyBytes_FromString(buf).decode()
        if _libxar.xar_prop_get(cur, b"uid", &buf) == 0:
            p["uid"] = int(PyBytes_FromString(buf))
        if _libxar.xar_prop_get(cur, b"group", &buf) == 0:
            p["gname"] = PyBytes_FromString(buf).decode()
        if _libxar.xar_prop_get(cur, b"gid", &buf) == 0:
            p["gid"] = int(PyBytes_FromString(buf))
        if _libxar.xar_prop_get(cur, b"type", &buf) == 0:
            p["type_string"] = PyBytes_FromString(buf).decode()
            try:
                p["type"] = XarFileType(p["type_string"])
            except ValueError:
                p["type"] = XarFileType.OTHER
        if _libxar.xar_prop_get(cur, b"mode", &buf) == 0:
            p["mode"] = int(PyBytes_FromString(buf), 8)
        if _libxar.xar_prop_get(cur, b"mtime", &buf) == 0:
            raw_mtime = PyBytes_FromString(buf).decode()
            p["mtime"] = datetime.fromisoformat(raw_mtime)
        # properties for specific file types
        if _libxar.xar_prop_get(cur, b"link", &buf) == 0:
            p["linkname"] = PyBytes_FromString(buf).decode()
            if p["type"] == XarFileType.LNK and p["linkname"] == "original":
                p["type"] = XarFileType.ORIG
        if _libxar.xar_prop_get(cur, b"device/major", &buf) == 0:
            p["devmajor"] = int(PyBytes_FromString(buf))
        if _libxar.xar_prop_get(cur, b"device/minor", &buf) == 0:
            p["devminor"] = int(PyBytes_FromString(buf))

        p["pointer"] = _XarFilePointer(
            self.archive,
            PyCapsule_New(<void*>cur, b"xar_file_t", NULL),
        )
        self.entry = XarInfo(**p)
        return self.entry


cdef class XarArchive:
    cdef readonly object path
    cdef _libxar.xar_t handle

    def __cinit__(self) -> None:
        self.path = None
        self.handle = NULL

    def __init__(self, path: str | pathlib.Path) -> None:
        path = pathlib.Path(path)
        if not path.exists():
            raise FileNotFoundError(str(path))
        self.handle = _libxar.xar_open(str(path).encode(), _libxar.READ)
        if self.handle == NULL:
            raise XarError("failed to open archive", str(path))
        self.path = path

    def __dealloc__(self) -> None:
        self.close()

    def __iter__(self) -> XarInfoIterator:
        return XarInfoIterator(self)

    def __repr__(self) -> str:
        return "<{} '{}'{}>".format(
            type(self).__name__,
            self.path,
            " (closed)" if self.closed else "",
        )

    def close(self) -> None:
        if self.handle != NULL:
            _libxar.xar_close(self.handle)
            self.handle = NULL

    @property
    def closed(self) -> bool:
        return self.handle == NULL

    def __enter__(self) -> typing.Self:
        if self.closed:
            raise XarError("cannot enter context with closed archive")
        return self

    def __exit__(self, a, b, c) -> None:
        self.close()

