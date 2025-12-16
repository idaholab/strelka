from __future__ import annotations
from enum import StrEnum
from hashlib import md5, sha1, sha256, sha384, sha512
import itertools
import stat
from typing import (
    Annotated,
    Any,
    ClassVar,
    Final,
    Hashable,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    Self,
    TypeVar,
    overload,
)
from uuid import UUID
import uuid

from pydantic import Field, PlainValidator, model_validator
from ssdeep import Hash as ssdeep
from tlsh import Tlsh as tlsh

from ..util.collections import get_nested
from .base import Model
from .serialize import serialize
from .types import Date, Octal


__all__ = (
    "File",
    "FileAttribute",
    "FileType",
    "Hash",
    "NULL_UUID",
    "Tree",
)


NULL_UUID: Final = uuid.UUID(int=0)
_T: Final = TypeVar("_T")
AnyData = bytes | bytearray | memoryview


class Hash(Model, frozen=True):
    cdhash: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    sha384: str | None = None
    sha512: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None

    @classmethod
    def for_data(cls, data: AnyData | Iterable[AnyData]) -> Self:
        hashes = {
            "md5": md5(),
            "sha1": sha1(),
            "sha256": sha256(),
            "sha384": sha384(),
            "sha512": sha512(),
            "ssdeep": ssdeep(),
            "tlsh": tlsh(),
        }

        if isinstance(data, (bytes, bytearray, memoryview)):
            data_iter = [data]
        else:
            data_iter = data

        for block in data_iter:
            for h in hashes.values():
                h.update(block)

        # Safely finalize TLSH
        try:
            hashes["tlsh"].final()
            tlsh_digest = hashes["tlsh"].hexdigest()
        except ValueError:
            # Data too short for TLSH
            tlsh_digest = None

        return cls(
            md5=hashes["md5"].hexdigest(),
            sha1=hashes["sha1"].hexdigest(),
            sha256=hashes["sha256"].hexdigest(),
            sha384=hashes["sha384"].hexdigest(),
            sha512=hashes["sha512"].hexdigest(),
            ssdeep=hashes["ssdeep"].digest(),
            tlsh=tlsh_digest,
        )


class Tree(Model, frozen=True):
    root: UUID
    node: UUID = NULL_UUID
    parent: UUID | None = None
    depth: int = 0

    @model_validator(mode="after")
    @staticmethod
    def _validate(this: Tree) -> Tree:
        # force our UUID/depth to be considered as "set"
        this.model_fields_set.update({"depth", "node"})
        # based on our depth, potentially fixup our other fields
        if this.depth == 0:
            object.__setattr__(this, "node", this.root)
            object.__setattr__(this, "parent", None)
        elif this.depth == 1:
            object.__setattr__(this, "parent", this.root)
        # if we still don't have a UUID, generate one
        if this.node == NULL_UUID:
            # prefer UUID7 if available (Python 3.14 and later), otherwise just use
            # UUID4 because it works fine enough for our purposes
            object.__setattr__(this, "uuid", getattr(uuid, "uuid7", uuid.uuid4)())
        return this

    def child(self, unique_key: Iterable[Hashable]) -> Self:
        # create a new child tree node using UUID5 to generate a "nested"/dependent
        # UUID based on the current file's UUID
        return type(self)(
            depth=(self.depth + 1),
            parent=self.node,
            root=self.root,
            node=uuid.uuid5(self.node, serialize(unique_key)),
        )


class FileAttribute(StrEnum):
    """
    Some common, source-agnostic file attributes.
    """

    hidden = "hidden"
    setgid = "setgid"
    setuid = "setuid"
    sticky = "sticky"
    system = "system"


class FileType(StrEnum):
    """
    The standard set of possible POSIX filetypes.
    """

    block_device = "block-device"
    char_device = "char-device"
    directory = "directory"
    door = "door"
    event_port = "event_port"
    fifo = "fifo"
    file = "file"
    hard_link = "hard-link"
    junction = "junction"
    socket = "socket"
    symlink = "symlink"
    whiteout = "whiteout"

    unknown = "unknown"


def _expand_mime_type(value: str | Iterable[str]) -> set[str]:
    if isinstance(value, str):
        value = [value]
    mimes = set()
    for e in value:
        if ";" in e:
            mimes.add(e.split(";", 1)[0])
        mimes.add(e)
    return mimes


class File(Model, frozen=True):
    EMPTY: ClassVar[File]

    tree: Tree
    has_data: Annotated[bool, Field(exclude=True)]
    pointer: str = Field(exclude=True, default="")
    source: str | None = None
    metadata: dict[str, Any] = {}
    flavors: dict[str, set[str]] = {}
    mime_type: Annotated[set[str], PlainValidator(_expand_mime_type)] = set()

    accessed: Date | None = None
    attributes: set[FileAttribute | str] = set()
    created: Date | None = None
    ctime: Date | None = None
    device: str | None = None
    directory: str | None = None
    drive_letter: str | None = None
    extension: str | None = None
    fork_name: str | None = None
    gid: str | int | None = None
    group: str | None = None
    hash: Hash | None = None
    inode: str | int | None = None
    mode: Octal | None = None
    mtime: Date | None = None
    name: str | None = None
    origin_referrer_url: str | None = None
    origin_url: str | None = None
    owner: str | None = None
    path: str | None = None
    size: int | None = None
    target_path: str | None = None
    type: FileType | str = FileType.file
    uid: str | int | None = None

    all_flavors: set[str] = Field(exclude=True, init=False, default_factory=set)

    @model_validator(mode="after")
    @staticmethod
    def _validate(this: File) -> File:
        def _set(k: str, v: Any) -> None:
            object.__setattr__(this, k, v)
            this.model_fields_set.add(k)

        # if we were given some (but not all) path/name/etc. values, expand as able
        if this.path:
            sep = "\\" if "\\" in this.path else "/"
            *_, parent, name = None, *this.path.rstrip(sep).rsplit(sep, 1)
            name, fork, *_ = *name.split(":", 1), None
            if not this.name:
                if name:
                    _set("name", name)
                elif this.path == sep:
                    _set("name", sep)
            if not this.directory:
                if parent:
                    _set("directory", parent)
                elif this.path == sep:
                    _set("directory", sep)
            if fork and not this.fork_name:
                _set("fork_name", fork)
        elif this.directory is not None and this.name:
            sep = "\\" if "\\" in this.directory else "/"
            _set("path", sep.join([this.directory, this.name]))
        if this.name:
            if not this.extension:
                *_, name, ext = None, *this.name.rsplit(".", 1)
                # filter out dotfiles from being one giant extension
                if name and ext:
                    _set("extension", ext)

        # we understand some common mode bits, so handle automatically extracting them
        # as attributes as well
        if this.mode is not None:
            attrs = set(this.attributes)
            if this.mode & stat.S_ISUID:
                attrs.add(FileAttribute.setuid)
            if this.mode & stat.S_ISGID:
                attrs.add(FileAttribute.setgid)
            if this.mode & stat.S_ISVTX:
                attrs.add(FileAttribute.sticky)
            if attrs:
                _set("attributes", attrs)

        # if we weren't explicitly given a pointer, use our UUID
        _set("pointer", str(this.pointer or this.tree.node))

        # generate a merged set of flavors to compare against when tasting
        _set(
            "all_flavors",
            {
                *itertools.chain(*this.flavors.values()),
                *this.mime_type,
            },
        )

        return this

    @overload
    def get_metadata(self, path: str, default: None = None) -> Any: ...
    @overload
    def get_metadata(self, path: str, default: _T) -> _T: ...

    def get_metadata(self, path: str, default: _T = None) -> _T | Any:
        return get_nested(self.metadata, path, default)

    @property
    def trace_attributes(self) -> Iterator[tuple[str, Any]]:
        yield "file.name", self.name or ""
        yield "file.path", self.path or ""
        yield "file.size", self.size
        yield "file.source", self.source or ""
        yield "file.pointer", self.pointer
        yield "file.tree.depth", self.tree.depth
        yield "file.tree.node", str(self.tree.node)
        yield "file.tree.parent", str(self.tree.parent or "")
        yield "file.tree.root", str(self.tree.root)
        for key, flavors in self.flavors.items():
            yield f"file.flavors.{key}", list(flavors)

    def child(
        self,
        unique_key: Iterable[Hashable],
        *,
        flavors: Mapping[str, Iterable[str]] | None = None,
        tree: Literal[None] = None,
        **kwargs,
    ) -> File:
        del tree
        return File.model_validate(
            {
                "flavors": {k: set(v) for k, v in (flavors or {}).items()},
                "tree": self.tree.child(unique_key),
                **kwargs,
            }
        )


File.EMPTY = File(
    tree=Tree(root=NULL_UUID),
    name=":empty",
    has_data=False,
)
