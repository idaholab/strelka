from __future__ import annotations
import contextlib
from importlib import resources
from importlib.resources.abc import Traversable
import os
from os import PathLike
from pathlib import Path
import shutil
from typing import Callable, Generic, Iterator, TypeVar
from datetime import datetime, UTC, timedelta, timezone

from . import ensure_string


__all__ = (
    "find_file",
    "safe_join_path",
    "find_executable",
)


_T = TypeVar("_T")


class FileCache(Generic[_T]):
    expire_after: timedelta | None

    _cache: dict[Path, tuple[datetime, _T]]

    def __init__(self, expire_after: timedelta | None = None) -> None:
        self.expire_after = expire_after
        self._cache = {}

    def load(self, path: Path, loader: Callable[[Path], _T]) -> _T:
        if not path.exists():
            raise FileNotFoundError(path)

        key = path.resolve()

        if path.is_dir():
            mtime = datetime.min.replace(tzinfo=UTC)
            for child in path.rglob("*"):
                if child.is_dir():
                    continue
                stat = child.stat()
                mtime = max(mtime, datetime.fromtimestamp(stat.st_mtime, UTC))
        else:
            stat = path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, UTC)

        now = datetime.now(UTC)

        (ts, result) = self._cache.get(key, (datetime.min.replace(tzinfo=UTC), None))
        if result is not None:
            if ((e := self.expire_after) and (now - ts) > e) or (mtime >= ts):
                self._cache.pop(key)
            else:
                return result

        self._cache[key] = (ts, (result := loader(path)))
        return result


# this is a contextmanager because -technically-, even though `Traversable`
# means `Path` in this specific instance, we cannot assume a Traversable is an
# actual file path except inside a with block of `.as_file()` or its ilk
@contextlib.contextmanager
def find_file(
    *paths: tuple[Path | str | None, ...] | Path | Traversable | str | None,
) -> Iterator[Path]:
    for path in paths:
        if isinstance(path, tuple):
            path = safe_join_path(*path)
        if not path:
            continue
        elif isinstance(path, Traversable):
            with resources.as_file(path) as rpath:
                if rpath.exists():
                    yield rpath
                    break
        else:
            path = Path(path)
            if path.exists():
                yield path
                break
    else:
        raise FileNotFoundError(list(map(str, filter(bool, paths))))


def safe_join_path(*parts: str | Path | None) -> Path | None:
    if not parts or any(p is None for p in parts):
        return None
    first, *rest = map(str, parts)
    return Path(first).joinpath(*rest)


def find_executable(
    program: str | bytes | PathLike | None,
    path: str | bytes | PathLike | None = None,
) -> str | None:
    # if we were given a path, convert it to a path, expand home directories, and check
    # to see if it is absolute (since relative paths make no sense in a config file),
    # exists, and is executable; if it doesn't, clear it out so we try to find it
    if path is not None:
        path = Path(ensure_string(path)).expanduser()
        if not (path.is_absolute() and path.is_file() and os.access(path, os.X_OK)):
            path = None
    # we either weren't given a path, or the path given didn't meet requirements; if we
    # were mistakenly given a full path as our program, try to use that, otherwise try
    # to look for the program in our path
    if path is None and program is not None:
        program = ensure_string(program)
        if os.sep in program:
            return find_executable(None, program)
        path = shutil.which(program)
    # return either our final, located executable path as a string, or None if we failed
    return str(path) if path is not None else None
