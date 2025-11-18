from __future__ import annotations
import builtins
import dataclasses
import functools
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    Sequence,
    Set,
    TYPE_CHECKING,
    Tuple,
    TypeGuard,
    TypeVar,
    cast,
    overload,
)

from typing_extensions import deprecated

from . import MISSING, _MISSING

if TYPE_CHECKING:
    from _typeshed import SupportsRichComparison, DataclassInstance
else:
    SupportsRichComparison = "_typeshed.SupportsRichComparison"
    DataclassInstance = "_typeshed.DataclassInstance"


__all__ = (
    "dataclass_to_dict",
    "filter_mapping",
    "first",
    "get_nested",
    "is_sequence",
    "ListCompatibleSet",
    "merge",
    "pop_nested",
    "set_nested",
    "SkipItem",
    "sorted_chain",
    "visit",
)


_ValueT = TypeVar("_ValueT", None, str, int, float, bool, list, Mapping, dict)
_K = TypeVar("_K")
_T = TypeVar("_T")
_V = TypeVar("_V")
_O = TypeVar("_O", bound=SupportsRichComparison, covariant=True)
_O1 = TypeVar("_O1", bound=SupportsRichComparison, covariant=True)
_O2 = TypeVar("_O2", bound=SupportsRichComparison, covariant=True)


class ListCompatibleSet(set[_T]):
    @deprecated("use ListCompatibleSet.add() instead")
    def append(self, value: _T) -> None:
        self.add(value)

    @deprecated("use ListCompatibleSet.update() instead")
    def extend(self, values: Iterable[_T]) -> None:
        self.update(values)


def is_sequence(value: Any, length: int = -1) -> TypeGuard[Sequence]:
    return isinstance(value, Sequence) and (length < 0 or len(value) == length)


def dataclass_to_dict(value: DataclassInstance) -> dict[str, Any]:
    d = dataclasses.asdict(value)
    return {
        f.name: d.get(f.name)
        for f in dataclasses.fields(value)
        if not f.name.startswith("_") and not f.metadata.get("exclude", False)
    }


def filter_mapping(
    func: Callable[[_V], Any] | None,
    mapping: Mapping[_K, _V],
) -> Iterator[tuple[_K, _V]]:
    for key, value in mapping.items():
        if (not func and value) or (func and func(value)):
            yield key, value


def first(
    items: Iterable[_T],
    *,
    filter: Callable[[_T], bool] | None = lambda _: True,
    default: _T | _MISSING = MISSING,
) -> _T:
    for item in builtins.filter(filter, items):
        return item
    if isinstance(default, _MISSING):
        raise ValueError("no items matched filter, and no default provided")
    return default


@overload
def merge(first: _MISSING, /, *rest: _MISSING) -> None: ...
@overload
def merge(first: _ValueT, /, *rest: _MISSING) -> _ValueT: ...
@overload
def merge(first: _MISSING, /, *rest: _ValueT | _MISSING) -> _ValueT: ...
@overload
def merge(first: Mapping, /, *rest: Mapping | _MISSING) -> Mapping: ...
@overload
def merge(first: Any, /, *rest: _ValueT | _MISSING) -> _ValueT: ...


def merge(first: Any, /, *rest: Any) -> Any:
    result = first
    for item in rest:
        if item is MISSING:
            pass
        elif result is MISSING:
            result = item
        elif isinstance(result, dict) and isinstance(item, dict):
            result = {
                k: merge(result.get(k, MISSING), item.get(k, MISSING))
                for k in {*result.keys(), *item.keys()}
            }
        else:
            result = item
    if result is MISSING:
        return None
    return result


class SkipItem(Exception):
    pass


VisitRecurse = Callable[[Any], Any]
VisitCallback = Callable[[Any, VisitRecurse], Any]


def _visit_iter(v: Iterator[Any], cb: VisitCallback) -> Iterator[Any]:
    while True:
        try:
            e = next(v)
        except StopIteration:
            break
        try:
            yield visit(e, cb)
        except SkipItem:
            continue


def visit(v: Any, cb: VisitCallback) -> Any:
    recurse = functools.partial(visit, cb=cb)
    if isinstance(v, (str, bytes, bytearray)):
        pass
    elif isinstance(v, Tuple):
        return cb(tuple(_visit_iter(iter(v), cb)), recurse)
    elif isinstance(v, Sequence):
        return cb(list(_visit_iter(iter(v), cb)), recurse)
    elif isinstance(v, Set):
        return visit(sorted(v), cb)
    elif isinstance(v, Mapping):
        return cb(dict(_visit_iter(iter(v.items()), cb)), recurse)
    return cb(v, recurse)


@overload
def sorted_chain(
    *iterables: Iterable[_O1],
    key: Callable[[_O1], _O2] = (lambda e: e),
) -> Iterator[_O1]: ...


@overload
def sorted_chain(
    *iterables: Iterable[_T],
    key: Callable[[_T], _O],
) -> Iterator[_T]: ...


def sorted_chain(
    *iterables: Iterable[_T],
    key: Callable[[_T], _O] = lambda e: cast(SupportsRichComparison, e),
) -> Iterator[_T]:
    iters = [(i, iter(it), MISSING) for i, it in enumerate(iterables)]

    def _next_iters(
        its: Iterable[tuple[int, Iterator[_T] | _MISSING, _T | _MISSING]],
    ) -> Iterator[tuple[int, Iterator[_T] | _MISSING, _T | _MISSING]]:
        for i, it, val in its:
            if isinstance(it, _MISSING):
                yield i, it, val
                continue
            if val is MISSING:
                try:
                    val = next(it)
                except StopIteration:
                    it = MISSING
            yield i, it, val

    while True:
        iters = list(_next_iters(iters))
        valid = [
            (i, it, val)
            for i, it, val in iters
            if not isinstance(it, _MISSING) and not isinstance(val, _MISSING)
        ]
        if not valid:
            break
        i, it, value = min(valid, key=lambda e: key(e[2]))
        iters[i] = (i, it, MISSING)
        yield value


def _split_nested_path(path: str) -> tuple[str | None, str]:
    *_, parent, name = None, *path.rsplit(".", 1)
    return parent, name


@overload
def _find_nested(
    config: dict,
    path: str | None,
    *,
    create: bool = False,
    missing_ok: Literal[False] = False,
) -> dict: ...


@overload
def _find_nested(
    config: dict,
    path: str | None,
    *,
    create: bool = False,
    missing_ok: Literal[True] = True,
) -> dict | None: ...


def _find_nested(
    config: dict,
    path: str | None,
    *,
    create: bool = False,
    missing_ok: bool = False,
) -> dict | None:
    if path is None:
        return config
    parts = path.split(".")
    for i, part in enumerate(parts):
        if part not in config:
            if missing_ok:
                return None
            elif create:
                config = config.setdefault(part, {})
            else:
                config = {}
        else:
            config = config[part]
        if not isinstance(config, dict):
            raise ValueError(
                "config value at '{}' is not a mapping".format(
                    ".".join(parts[: i + 1]),
                )
            )
    return config


@overload
def get_nested(config: dict, path: str, default: None = None) -> Any: ...
@overload
def get_nested(config: dict, path: str, default: _T) -> _T: ...


def get_nested(config: dict, path: str, default: Any = None) -> Any:
    parent, name = _split_nested_path(path)
    return _find_nested(config, parent).get(name, default)


def set_nested(config: dict, path: str, value: Any) -> None:
    parent, name = _split_nested_path(path)
    _find_nested(config, parent, create=True)[name] = value


def pop_nested(config: dict, path: str) -> None:
    parent, name = _split_nested_path(path)
    target = _find_nested(config, parent, missing_ok=True)
    if target is None or name not in target:
        raise KeyError(path)
    target.pop(name, None)
