from __future__ import annotations
from dataclasses import dataclass
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec, NamespaceLoader, SourceFileLoader
from importlib.readers import MultiplexedPath
from importlib.resources.abc import Traversable, TraversableResources
from importlib.util import spec_from_file_location
from itertools import chain
import logging
import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Final, Iterable, Self, Sequence

import yaml

import strelka

from .metadata import Metadata


_NamespacePath = Any


PLUGIN_PATH_ENV_VAR: Final = "STRELKA_PLUGIN_PATH"
CACHE_TAG: Final = sys.implementation.cache_tag
MULTIARCH_CACHE_TAG: Final = "-".join([CACHE_TAG, sys.implementation._multiarch])


@dataclass(repr=False)
class Plugin:
    name: str
    paths: list[Path]
    metadata: Metadata
    namespaces: dict[str, Path]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


class PluginFileReader(TraversableResources):
    loader: PluginSourceFileLoader

    def __init__(self, loader) -> None:
        self.loader = loader

    def files(self) -> Traversable:
        # implement the `files()` capability by return a `MultiplexedPath` as
        # our `Traversable` instead of the default just returning a single path
        return MultiplexedPath(*self.loader.search_paths)


class PluginSourceFileLoader(SourceFileLoader):
    search_paths: list[Path]

    @classmethod
    def from_spec(cls, spec: ModuleSpec) -> Self:
        """
        Simple hook to allow cloning a module spec (with a `SourceFileLoader`
        already populated) with its submodule search locations.
        """
        assert isinstance(
            spec.loader, SourceFileLoader
        ), "cannot copy non-SourceFileLoader instance"
        return cls(
            spec.loader.name,
            spec.loader.path,
            spec.submodule_search_locations or (),
        )

    def __init__(
        self,
        fullname: str,
        path: str | Path,
        search_paths: Iterable[str | Path] = (),
    ) -> None:
        super().__init__(fullname, str(path))
        self.search_paths = list(map(Path, search_paths))

    def get_resource_reader(  # type: ignore
        self,
        name: str | None = None,
    ) -> PluginFileReader | None:
        # (this is consistent with the stock loader) only handle our name
        if (name := name or self.name) is not self.name:
            raise ImportError(f"loader for {self.name} cannot handle {name}")
        # if we aren't a package, return `None` (which is per the spec)
        if not self.is_package(name):
            return None
        # return a file reader for our paths
        return PluginFileReader(self)


class PluginNamespaceLoader(NamespaceLoader):
    """
    NOTE: this is all considered -INTERNAL- to the CPython implementation, so...
          it seems to work consistently and Pypy implements the same structures,
          but YMMV, especially if the Python version Strelka runs on is updated
    """

    @staticmethod
    def default_path_finder(
        name: str,
        parent_name: tuple[str, ...],
    ) -> ModuleSpec:
        logging.warning(f"default_path_finder({name!r}, {parent_name!r})")
        # [ES]: The `path_finder` parameter to `__init__` is typed incorrectly,
        #       the implementation of `_NamespacePath` (which is where the
        #       `path_finder` is used) supports a return of `None` and just
        #       doesn't recalculate; it's tied to cache invalidation, and I
        #       haven't seen it used, so... for now, just do this, and hope it
        #       all works out? It'd be nice if we either didn't have to
        #       instantiate these types ourselves, or they weren't internal
        #       implementations, but it is what it is.
        return None  # type: ignore

    @property
    # importing this type is a pain, it's not exported anywhere
    def path(self) -> _NamespacePath:  # type: ignore
        # this is a private attribute, so we "can't" access it here cleanly
        return getattr(self, "_path")


class PluginPathFinder(MetaPathFinder):
    paths: list[Path]
    __plugin_cache: dict[str, Plugin]
    __spec_cache: dict[str, ModuleSpec | None]

    def __init__(self, paths: Iterable[Path]) -> None:
        self.paths = [p.absolute() for p in paths]
        self.__plugin_cache = {}
        self.__spec_cache = {}

    def build_plugin(
        self,
        name: str,
        paths: Iterable[Path],
        metadata: Metadata,
        *,
        prefix: str = "",
        ns_glob: str = "**/*/",
    ) -> None:
        # materialize our set of paths
        paths = list(paths)
        # check to see if it's a plugin name we've already seen
        if (plugin := self.__plugin_cache.get(name)) is not None:
            # okay, if it's the same thing, skip it
            if plugin.paths == paths:
                return
            # it's not, we have plugins that share a name, that's bad
            logging.error(
                "multiple plugins named '{}', skipping [{}]".format(
                    name,
                    ", ".join(map(str, paths)),
                )
            )
        else:
            logging.info("registering plugin '{}'".format(name))
            logging.debug(
                "plugin '{}' found at: {}".format(
                    name,
                    ", ".join(map(str, paths)),
                )
            )
        # split our prefix into items (if we were given one)
        prefix_parts = prefix.strip(".").split(".") if prefix else ()
        # figure out all of our namespaces
        namespaces = {}
        for path in paths:
            namespaces.update(
                {
                    ".".join(chain(prefix_parts, p.relative_to(path).parts)): p
                    for p in set(path.rglob(ns_glob))
                }
            )
        # it's something new, create the new plugin object and cache
        self.__plugin_cache[name] = Plugin(
            name=name,
            paths=paths,
            metadata=metadata,
            namespaces=namespaces,
        )

    def load_metadata(self, path: Path) -> Metadata:
        with path.open("rb") as fh:
            data = yaml.safe_load(fh)
        return Metadata.model_validate({**data, "raw": data})

    def scan_plugins(self) -> None:
        # build a fake "plugin" for the base strelka location(s)
        base_paths = list(map(Path, strelka.__path__))
        scanners = set()
        for path in base_paths:
            if not (inner := path / "scanners").exists():
                continue
            scanners.update(
                p.stem.removeprefix("scan_")
                for p in inner.iterdir()
                if p.stem.startswith("scan_")
            )
        self.build_plugin(
            "strelka",
            base_paths,
            Metadata.model_validate(
                {
                    "name": "strelka",
                    "version": strelka.__version__,  # type: ignore
                    "summary": "The Strelka core",
                    "scanners": {n: {} for n in sorted(scanners)},
                }
            ),
            prefix="strelka",
        )
        # walk through the search paths we were given looking for plugins
        for path in chain(*(p.glob("*/") for p in self.paths)):
            # in order to be a plugin, it needs a metadata YAML file
            if not (info_path := path / "plugin.yaml").exists():
                continue
            # it's a plugin, construct it into the cache
            self.build_plugin(
                path.name,
                [path],
                self.load_metadata(info_path),
            )

    def find_spec(
        self,
        name: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        # if it's not actually something inside strelka, bail
        if not name.startswith("strelka."):
            return None
        # if it's already been handled, just return the same spec
        if name in self.__spec_cache:
            return self.__spec_cache[name]
        # scan for any plugins in paths we were given
        if not self.__plugin_cache:
            self.scan_plugins()
        # split our name into a parent/module pair, or ""/module if top-level
        *_, parentname, thisname = "", *name.rsplit(".", 1)
        # walk through all of our discovered plugins
        src = []
        search = []
        for plugin in self.__plugin_cache.values():
            par_path = plugin.namespaces.get(parentname)
            # if an associated module script exists, store that
            if par_path and (this_path := par_path / f"{thisname}.py").exists():
                src.append((plugin, this_path))
            # if a compiled module exists, store that
            elif (
                par_path
                and (
                    this_path := par_path / f"{thisname}.{MULTIARCH_CACHE_TAG}.so"
                ).exists()
            ):
                src.append((plugin, this_path))
            # otherwise check if we know about this module as a namespace directory
            elif (this_path := plugin.namespaces.get(name)) is not None:
                # if it has initialization code, store that
                if (init_path := this_path / "__init__.py").exists():
                    src.append((plugin, init_path))
                # and regardless, store its submodule lookup path
                search.append((plugin, this_path))
        # if we found nothing, it doesn't exist, bail now
        if not src and not search:
            return None
        # if we found multiple source files, that's bad, complain
        if len(src) > 1:
            raise ImportError(
                "\n  ".join(
                    map(
                        str,
                        [
                            f"conflicting '__init__.py' files for '{name}':",
                            *(p for _, p in src),
                        ],
                    )
                )
            )
        # we hook the creating a namespace package spec (i.e. no source files)
        # because we've had really inconsistent results with having Python
        # correctly handle it
        if not src:
            # create our loader so we can reference it again
            loader = PluginNamespaceLoader(
                name,
                [p for _, p in search],
                # see notes above about this function
                PluginNamespaceLoader.default_path_finder,
            )
            # build our module spec given the loader
            spec = ModuleSpec(name, loader=loader, origin=None)
            # and fix the search locations to be the `_NamespacePath` object
            spec.submodule_search_locations = loader.path
        # otherwise, build a spec for it
        else:
            spec = spec_from_file_location(
                name,
                src[0][1] if src else None,
                submodule_search_locations=[p for _, p in search] or None,
            )
        # if we ended up with a spec, potentially replace some bits
        if spec:
            # if the loader ended up being a `SourceFileLoader`, replace it with
            # our own, hooked version that fixes passing along multiple search
            # paths to any resource finding (stock does not)
            if isinstance(spec.loader, SourceFileLoader):
                spec.loader = PluginSourceFileLoader.from_spec(spec)
            # "fix" cache paths so that bytecode isn't cached with plugins
            if spec.cached:
                cached = Path(spec.cached)
                # if it's outside the base tree(s), just tell it to not cache
                if not any(map(cached.is_relative_to, strelka.__path__)):
                    spec.cached = None
        # store our resulting spec (or lack thereof), and return
        self.__spec_cache[name] = spec
        return spec

    def invalidate_caches(self) -> None:
        # clear out our two internal caches
        self.__plugin_cache.clear()
        self.__spec_cache.clear()


__finder: PluginPathFinder | None = None


def register_plugin_paths(paths: Iterable[str | Path]) -> None:
    global __finder
    paths = (Path(p).resolve() for p in paths)
    if __finder is None:
        __finder = PluginPathFinder(paths)
        sys.meta_path.insert(0, __finder)
    else:
        __finder.paths.extend([p for p in paths if p not in __finder.paths])
        __finder.invalidate_caches()
        __finder.scan_plugins()


def register_env_plugin_paths() -> None:
    register_plugin_paths(
        filter(
            bool,
            os.getenv(PLUGIN_PATH_ENV_VAR, "").split(os.pathsep),
        )
    )


def get_search_paths() -> Iterable[Path]:
    return [
        *(Path(p).parent for p in strelka.__path__),
        *(f.paths if (f := __finder) else ()),
    ]
