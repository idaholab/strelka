import argparse
import datetime
from importlib import resources
import logging
from pathlib import Path
import uuid

from strelka.model.file import Tree
from strelka.util import now

from .backend import Task
from .backend.local import LocalBackend
from .config import BackendConfig
from .model import File, serialize
from .util.files import find_file
from .util.collections import get_nested, set_nested
from .plugins import register_plugin_paths


RSRC_BASE = resources.files("strelka.config")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="strelka-standalone",
    )
    parser.add_argument(
        "-P", "--path",
        metavar="DIR",
        default=[],
        type=Path,
        action="append",
        help="additional location(s) to find plugins",
    )
    parser.add_argument(
        "-p",
        "--config-dir",
        metavar="DIR",
        type=Path,
        help="path to backend configuration directory",
    )
    parser.add_argument(
        "-c",
        "--backend-cfg-path",
        metavar="PATH",
        type=Path,
        help="path to backend configuration file",
    )
    parser.add_argument(
        "-l",
        "--logging-cfg-path",
        metavar="PATH",
        type=Path,
        help="path to logging configuration file",
    )
    parser.add_argument(
        "-Y",
        "--yara-tasting-rules",
        metavar="PATH",
        type=Path,
        help="path to tasting YARA rules",
    )
    parser.add_argument(
        "-y",
        "--yara-scanning-rules",
        metavar="PATH",
        type=Path,
        help="path to scanning YARA rules",
    )
    parser.add_argument(
        "-t",
        "--tlsh-rules",
        metavar="PATH",
        type=Path,
        help="path to TLSH rules",
    )
    parser.add_argument(
        "-U",
        "--root-uid",
        type=uuid.UUID,
        metavar="UUID",
        default=uuid.uuid4(),
        help="specify a root file ID",
    )
    parser.add_argument(
        "-x",
        "--disable-tracing",
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
        config = BackendConfig(backend_cfg_path)
        cfg_dir = backend_cfg_path.parent

        with (
            find_file(
                args.logging_cfg_path,
                (cfg_dir, config.get("logging_cfg")),
                (args.config_dir, "logging.yaml"),
                RSRC_BASE / "logging.yaml",
            ) as logging_cfg_path,
            find_file(
                args.yara_tasting_rules,
                (cfg_dir, config.get("tasting.yara_rules")),
                (args.config_dir, "taste", "taste.yara"),
                RSRC_BASE / "taste.yara",
            ) as taste_rules,
            find_file(
                args.yara_scanning_rules,
                (args.config_dir, "yara", "rules.yara"),
                RSRC_BASE / "rules.yara",
            ) as scan_rules,
            find_file(
                args.tlsh_rules,
                (args.config_dir, "tlsh", "rules.yaml"),
                RSRC_BASE / "tlsh.yaml",
            ) as tlsh_rules,
        ):
            config["tasting.yara_rules"] = str(taste_rules)
            config["logging_cfg"] = str(logging_cfg_path)
            config.configure_logging()

            # now register our plugin paths, since we have logging set up
            logging.debug("considering plugins in:")
            for path in args.path:
                logging.debug(" - {}".format(path))
            register_plugin_paths(args.path)

            # patch YARA scanner rules locations
            for rule in config.get("scanners.ScanYara", ()):
                loc = get_nested(rule, "options.location")
                if not loc or not Path(loc).exists():
                    set_nested(rule, "options.location", str(scan_rules))

            # patch TLSH scanner rules locations
            for rule in config.get("scanners.ScanTlsh", ()):
                loc = get_nested(rule, "options.location")
                if not loc or not Path(loc).exists():
                    set_nested(rule, "options.location", str(tlsh_rules))

            # provide a hook for disabling tracing, since standalone may not
            # have a valid jaeger/whatever server running
            if args.disable_tracing:
                config.pop("telemetry.traces.exporter")

            # create our backend using the loaded config file
            backend = LocalBackend(config)
            logging.info("starting local analysis...")

            # guesstimate when we ought to expire
            expire_at = now() + datetime.timedelta(minutes=15)

            # create our file object to analyze
            file = File(
                path=str(args.filename),
                tree=Tree(root=args.root_uid),
                has_data=True,
            )

            # store data in the backend for our file
            with args.filename.open("rb") as analysis_file:
                backend.store_file_data(file, analysis_file.read(), expire_at)

            # create a new task for our file, then perform analysis, dumping out events
            # as they are received
            task = Task.for_file(file, expire_at)
            for event in backend.distribute(task):
                print(event)
                print(serialize(event))


if __name__ == "__main__":
    main()
