from __future__ import annotations
import contextlib
from importlib import resources
from importlib.resources.abc import Traversable
import os
from pathlib import Path
import shutil
from typing import Iterator


__all__ = (
    "find_file",
    "safe_join_path",
    "find_executable",
)


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


def find_executable(program: str, path: str | Path | None) -> str | None:
    # if we were given a path, expand home directories and check to see if it is
    # absolute (since relative paths make no sense in a config file), exists, and is
    # executable; if it doesn't, clear it out so we can try to find it instead
    if path:
        path = Path(path).expanduser()
        if not (path.is_absolute() and path.is_file() and os.access(path, os.X_OK)):
            path = None
    # we either weren't given a path, or the path given didn't meet requirements; try to
    # look for the program in our path, if we can't find it, just bail
    if path is None:
        path = shutil.which(program)
        if path is None:
            return None
    # success: we have a location!
    return str(path)
