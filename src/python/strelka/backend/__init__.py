from __future__ import annotations
from abc import ABCMeta, abstractmethod
import importlib
import logging
import os
from pathlib import Path
import re
import string
from typing import Final, Iterator, Optional, TypedDict
import uuid

import inflection
import magic
from opentelemetry import trace
import yara

from ..config import BackendConfig
from ..exceptions import DistributionTimeout
from ..model import Date, Event, File
from ..scanners import Scanner
from ..telemetry.traces import SpanCreatorMixin, get_tracer
from ..util.files import FileCache
from ..util.timeout import timeout_after
from .task import Task


ENCODED_WHITESPACE: Final = string.whitespace.encode()


class ScannerMatch(TypedDict):
    name: str
    priority: int
    options: dict
    match: dict


class BaseBackend(SpanCreatorMixin, metaclass=ABCMeta):
    scanner_cache: dict[str, Scanner]
    config: BackendConfig
    tracer: trace.Tracer

    compiled_magic: magic.Magic
    yara_rules_cache: FileCache[yara.Rules]

    def __init__(
        self,
        config: BackendConfig,
    ) -> None:
        self.scanner_cache = {}
        self.config = config
        self.coordinator = None

        # create a tracer using the parameters in the config file
        self.tracer = get_tracer(
            self.config.get("telemetry.traces", {}),
            meta={
                "strelka.config.version": self.config.get("version", ""),
                "strelka.config.sha1": self.config.get("sha1", ""),
            },
        )

        # try to instantiate our file magic taster
        magic_db = self.config.get("tasting.mime_db", None) or None
        if magic_db and not os.path.exists(magic_db):
            logging.warning(
                "libmagic tasting DB does not exist: %s",
                magic_db,
            )
            magic_db = None
        self.compiled_magic = magic.Magic(magic_file=magic_db, mime=True)

    @staticmethod
    def _compile_yara_rules(path: Path) -> yara.Rules:
        if path.is_dir():
            return yara.compile(
                filepaths={
                    f"namespace{i}": str(entry)
                    for i, entry in enumerate(path.glob("**/*.yar*"))
                },
            )
        elif path.is_file():
            return yara.compile(filepath=str(path))
        else:
            logging.warning("YARA rules do not exist: %s", path)
            return yara.compile(source="")

    def taste_mime(self, data: bytes) -> Iterator[str]:
        """Tastes file data with libmagic."""
        yield self.compiled_magic.from_buffer(data)

    def taste_yara(
        self,
        data: bytes,
        *,
        remove_whitespace: bool = True,
    ) -> Iterator[str]:
        """Tastes file data with YARA."""

        # yield any matching rules for the data as-is
        rules = self.yara_rules_cache.load(
            Path(self.config.get("tasting.yara_rules", "/etc/strelka/taste")),
            self._compile_yara_rules,
        )
        for match in rules.match(data=data):
            yield match.rule
        # then, if the data starts with any whitespace, yield any matches with
        # that whitespace removed; because the recursive call won't have any
        # leading whitespace, this won't recurse more than once
        if remove_whitespace and data and data[0] in ENCODED_WHITESPACE:
            yield from self.taste_yara(data.lstrip(ENCODED_WHITESPACE))

    def get_scanner(self, name: str) -> Scanner:
        # if we are caching scanner instances and already have created an
        # instance for this scanner, just short-circuit and return it
        caching = self.config.get("caching.scanner", True)
        if caching and name in self.scanner_cache:
            return self.scanner_cache[name]
        # import the associated scanner module and instantiate the scanner class
        mod_name = inflection.underscore(name)
        module = importlib.import_module(f"strelka.scanners.{mod_name}")
        instance = getattr(module, name)(self)
        # if we're caching, store the instance
        if caching:
            self.scanner_cache[name] = instance
        # either way, return our new instance
        return instance

    def distribute(self, task: Task, file: File | None = None) -> Iterator[Event]:
        """Distributes a file through scanners.

        Args:
            task (Task): Task that the analysis is being performed for
            file (File | None): File that is being analyzed; if not specified,
                    the root file from the task will be scanned
        Returns:
            An iterator that generates scanning events for the submitted file
        """

        task.attach_trace_context()

        # build our list of files to process; we will add any children as they
        # are produced, but this way we won't need to do recursive calls
        processing = [file or task.file]
        while processing:
            file = processing.pop()
            event = Event(expire_at=task.expire_at, file=file)

            try:
                if not file.has_data:
                    logging.info(
                        "skipping distribution of file %s for %s because it has no associated data",
                        file.tree.node,
                        task,
                    )
                    yield event
                    continue

                with timeout_after(
                    self.config.get("limits.distribution", 600),
                    DistributionTimeout,
                ):
                    # ensure we have file data, however this backend handles that; if we
                    # don't have any file data (for whatever reason), log it, generate a
                    # (probably minimal) file event, and move on
                    data = self.retrieve_file_data(file)
                    if data is None:
                        logging.error(
                            "file %s for %s has no file data, skipping",
                            file.tree.node,
                            task,
                        )
                        yield event
                        continue

                    # okay, we have file data, now try to taste it and merge whatever we
                    # discover with the existing file object; log any failures, but that
                    # doesn't -inherently- mean we can't continue processing (we could
                    # have gotten some external flavors that still allow matches)
                    try:
                        with self.start_span("taste", attributes=file):
                            # add flavors if they haven't already been populated
                            file = file.model_merge(
                                {
                                    "mime_type": {
                                        *file.mime_type,
                                        *self.taste_mime(data),
                                    },
                                    "flavors": {
                                        "yara": {
                                            *self.taste_yara(data),
                                        },
                                    },
                                }
                            )
                            event.file = file
                    except Exception:
                        logging.exception(
                            "tasting file %s for %s failed",
                            file.tree.node,
                            task,
                        )

                    # if we have exceeded our maximum depth, log that, yield the file
                    # event (even if it has no scans attached) and move on
                    if file.tree.depth > self.config.get("limits.max_depth", 15):
                        logging.info(
                            "file %s of task %s exceeded maximum depth",
                            file.tree.node,
                            task,
                        )
                        yield event
                        continue

                    with self.start_span("scan", attributes=file):
                        # get list of matching scanners
                        scanner_list = self.match_scanners(file)

                        # create a new results set, then actually perform the scans
                        # for any rules that matched
                        for rule in scanner_list:
                            # try to get a scanner instance for this rule
                            try:
                                scanner = self.get_scanner(rule["name"])
                            except ModuleNotFoundError:
                                logging.exception(
                                    "scanner %s not found",
                                    rule["name"],
                                )
                                continue
                            # run the scanner and merge the scanner-specific results
                            # into our combined file event
                            event.update(
                                scanner.scan_wrapper(
                                    data,
                                    file,
                                    rule["options"],
                                    task.expire_at,
                                )
                            )
                            # clear the scanner after each use
                            scanner.clear()

            except DistributionTimeout:
                logging.exception(
                    "file %s of %s timed out during distribution",
                    file.tree.node,
                    task,
                )

            # add any children back to the iterative queue
            processing.extend(event.children)
            # finally pass this file's event outward
            yield event

    def match_scanner(
        self,
        scanner: str,
        rules: list,
        file: File,
        ignore_wildcards: Optional[bool] = False,
    ) -> ScannerMatch | None:
        """Tries to match a scanner to a given file, based on flavors, etc.

        Determines whether or not any of the rules for a scanner match a given
        file, based on flavors, filename, source, and UUID. Rules support
        positive and negative matching: rules are disqualified if any negative
        categories match, and are matched if any positive categories match.
        Flavors, sources, and UUIDs are literal matches, filenames use regexes.

        Args:
            scanner: name of the scanner to be assigned
            rules: list of matching rules as dictionaries
            file: file being considered for matches
            ignore_wildcards: whether to filter out wildcard matches
        Returns:
            Dictionary containing information about a matched scanner rule, or
            None if no rules successfully matched
        """
        for rule in rules:
            negatives = rule.get("negative", {})
            neg_flavors = set(negatives.get("flavors", []))
            neg_filename = negatives.get("filename", None)
            neg_source = set(negatives.get("source", []))
            neg_uids = {uuid.UUID(u) for u in negatives.get("uids", [])}

            if (
                (file.source in neg_source)
                or (file.tree.node in neg_uids)
                or (neg_filename and re.search(neg_filename, str(file.name or "")))
                or (neg_flavors & file.all_flavors)
            ):
                return None

            positives = rule.get("positive", {})
            pos_flavors = set(positives.get("flavors", []))
            pos_filename = positives.get("filename", None)
            pos_source = set(positives.get("source", []))
            pos_uids = {uuid.UUID(u) for u in positives.get("uids", [])}

            if (
                (file.source in pos_source)
                or (file.tree.node in pos_uids)
                or (pos_filename and re.search(pos_filename, str(file.name or "")))
                or ("*" in pos_flavors and not ignore_wildcards)
                or (pos_flavors & file.all_flavors)
            ):
                return ScannerMatch(
                    name=scanner,
                    priority=rule.get("priority", 5),
                    options=rule.get("options", {}),
                    match=rule,
                )

        return None

    def match_scanners(
        self, file: File, ignore_wildcards: bool = False
    ) -> list[ScannerMatch]:
        """Find any matching scanner rules from our config for a given file.

        Args:
            file: file to consider when matching
            ignore_wildcards: whether to filter out wildcard matches
        Returns:
            List of dictionaries containing matching scanner rule information
        """
        scanner_list = []
        for name, rules in self.config.get("scanners", {}).items():
            scanner = self.match_scanner(name, rules, file, ignore_wildcards)
            if scanner:
                scanner_list.append(scanner)
        return sorted(
            scanner_list,
            key=lambda k: k["priority"],
            reverse=True,
        )

    @abstractmethod
    def retrieve_file_data(
        self,
        file: File,
    ) -> bytes | None: ...

    @abstractmethod
    def store_file_data(
        self,
        file: File,
        data: bytes | bytearray | memoryview[int],
        expire_at: Date,
    ) -> None: ...
