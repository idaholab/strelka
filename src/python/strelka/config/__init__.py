from __future__ import annotations
import hashlib
import json
import logging
import logging.config
import os
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, MutableMapping, overload

import yaml

from ..util import _MISSING
from ..util.collections import get_nested, merge, pop_nested, set_nested


Options = Mapping[str, Any]
OptionsItems = Mapping[str, Any] | Iterator[tuple[str, Any]] | Iterable[tuple[str, Any]]


class BackendConfig(MutableMapping):
    dictionary: dict

    @overload
    def __init__(self, config: str | Path) -> None: ...
    @overload
    def __init__(self, config: Options) -> None: ...
    @overload
    def __init__(self, config: None = None) -> None: ...

    def __init__(self, config: str | Path | Options | None = None) -> None:
        if isinstance(config, (str, Path)):
            config_path = Path(config)

            if not config_path.exists():
                raise FileNotFoundError(f"backend config {config_path} does not exist")

            try:
                with config_path.open("rb") as fh:
                    self.dictionary = yaml.safe_load(fh)
            except yaml.YAMLError:
                logging.exception("backend configuration contains invalid YAML")
                raise

            logging.info(f"loaded backend configuration from {config_path}")

        elif config is None:
            self.dictionary = {}
        else:
            self.dictionary = dict(**config)

        self._hash_config()

    def _hash_config(self) -> str:
        self.dictionary["sha1"] = None
        serialized = json.dumps(
            self.dictionary,
            indent=None,
            separators=(",", ":"),
            sort_keys=True,
        )
        sha1 = hashlib.sha1(serialized.encode()).hexdigest()
        self.dictionary["sha1"] = sha1
        return sha1

    def configure_logging(self):
        log_cfg_path = self.dictionary.get("logging_cfg")
        if log_cfg_path and os.path.exists(log_cfg_path):
            with open(log_cfg_path) as f:
                logging.config.dictConfig(yaml.safe_load(f.read()))

    def update_if_missing(self, what: OptionsItems) -> None:
        self.dictionary = dict(merge(dict(what), self.dictionary))
        self._hash_config()

    def options_for_scanner(
        self,
        scanner: str,
        *options: Mapping[str, Any] | _MISSING,
        **kwargs,
    ) -> Mapping[str, Any]:
        return merge(
            # global, scanner-independent options
            self.get("options.global", {}),
            # global, rule-independent scanner options
            self.get(f"options.{scanner}", {}),
            # additional, explicit options
            *options,
            kwargs,
        )

    def __getitem__(self, path: str) -> Any:
        value = get_nested(self.dictionary, path, ...)
        if value is ...:
            raise KeyError(path)
        return value

    def __setitem__(self, path: str, value: Any) -> None:
        set_nested(self.dictionary, path, value)
        self._hash_config()

    def __delitem__(self, path: str) -> None:
        pop_nested(self.dictionary, path)
        self._hash_config()

    def __iter__(self) -> Iterator[str]:
        yield from self.dictionary.keys()

    def __len__(self) -> int:
        return len(self.dictionary)
