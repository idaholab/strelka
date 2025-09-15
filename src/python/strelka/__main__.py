import argparse
import contextlib
from importlib.resources.abc import Traversable
import logging
import os
import sys
import time
import uuid
from importlib import resources
from pathlib import Path
from typing import Iterator

from .config import BackendConfig
from . import strelka


RSRC_BASE = resources.files("strelka.config")


def main():
    parser = argparse.ArgumentParser(
        prog="strelka",
        # description="",
        # usage="%(prog)s [options]",
    )
    parser.add_argument(
        "-p", "--config-dir",
        metavar="DIR",
        type=Path,
        help="path to backend configuration directory",
    )
    parser.add_argument(
        "-c", "--backend-cfg-path",
        metavar="PATH",
        type=Path,
        help="path to backend configuration file",
    )
    parser.add_argument(
        "-l", "--logging-cfg-path",
        metavar="PATH",
        type=Path,
        help="path to logging configuration file",
    )
    parser.add_argument(
        "-Y", "--yara-tasting-rules",
        metavar="PATH",
        type=Path,
        help="path to tasting YARA rules",
    )
    parser.add_argument(
        "-y", "--yara-scanning-rules",
        metavar="PATH",
        type=Path,
        help="path to scanning YARA rules",
    )
    parser.add_argument(
        "-t", "--tlsh-rules",
        metavar="PATH",
        type=Path,
        help="path to TLSH rules",
    )
    parser.add_argument(
        "-U", "--root-uid",
        type=uuid.UUID,
        metavar="UUID",
        default=uuid.uuid4(),
        help="specify a root file ID",
    )
    parser.add_argument(
        "-x", "--disable-tracing",
        action="store_true",
        default=False,
        help="disable tracing for this run",
    )
    parser.add_argument(
        "filename",
        type=Path,
        help="the file to scan with Strelka",
    )

    args = parser.parse_args()

    with find_file(
        args.backend_cfg_path,
        (args.config_dir, "backend.yaml"),
        RSRC_BASE / "backend.yaml",
    ) as backend_cfg_path:
        print(backend_cfg_path)
        config = BackendConfig(backend_cfg_path)
        cfg_dict = config.dictionary
        cfg_dir = backend_cfg_path.parent

        with (
            find_file(
                args.logging_cfg_path,
                (cfg_dir, cfg_dict.get("logging_cfg")),
                (args.config_dir, "logging.yaml"),
                RSRC_BASE / "logging.yaml",
            ) as logging_cfg_path,
            find_file(
                args.yara_tasting_rules,
                (cfg_dir, cfg_dict.setdefault("tasting", {}).get("yara_rules")),
                (args.config_dir, "taste", "taste.yara"),
                RSRC_BASE / "taste.yara",
            ) as yara_tasting_rules,
            find_file(
                args.yara_scanning_rules,
                (args.config_dir, "yara", "rules.yara"),
                RSRC_BASE / "rules.yara",
            ) as yara_scanning_rules,
            find_file(
                args.tlsh_rules,
                (args.config_dir, "tlsh", "rules.yaml"),
                RSRC_BASE / "tlsh.yaml",
            ) as tlsh_rules,
        ):
            cfg_dict.setdefault("scanners", {})
            cfg_dict["tasting"]["yara_rules"] = str(yara_tasting_rules)
            cfg_dict["logging_cfg"] = str(logging_cfg_path)
            config.configure_logging()

            # patch YARA scanner rules locations
            for rule in cfg_dict["scanners"].get("ScanYara", ()):
                loc = rule.setdefault("options", {}).get("location")
                if not loc or not Path(loc).exists():
                    rule["options"]["location"] = str(yara_scanning_rules)

            # patch TLSH scanner rules locations
            for rule in cfg_dict["scanners"].get("ScanTlsh", ()):
                loc = rule.setdefault("options", {}).get("location")
                if not loc or not Path(loc).exists():
                    rule["options"]["location"] = str(tlsh_rules)

            if args.disable_tracing:
                cfg_dict.get("telemetry", {}).get("traces", {}).pop("exporter", None)

            backend = strelka.Backend(cfg_dict, disable_coordinator=True)

            with args.filename.open("rb") as analysis_file:
                file = strelka.File(
                    name=str(args.filename),
                    data=analysis_file.read(),
                    uid=args.root_uid,
                )
                logging.info("starting local analysis...")
                events = backend.distribute(file.uid, file, int(time.time()) + 300)
                for event in events:
                    print(strelka.format_event(event))


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


if __name__ == "__main__":
    main()
