import datetime
from itertools import count
from pathlib import Path
import re
import subprocess
import tempfile
from typing import ClassVar

import inflection

from . import File, Options, Scanner
from ..model import Date, FileType, Hash


class ScanDmg(Scanner):
    """Extracts files from DMG images"""

    EXCLUDED_ROOT_DIRS: ClassVar = {
        "[SYSTEM]",
    }
    SKIPPED_EXTATTRS: ClassVar = {
        "com.apple.quarantine",
        "com.apple.FinderInfo",
    }
    FILE_MODE_MAPPING: ClassVar = {
        "D": "directory",
        "R": "readonly",
        "H": "hidden",
        "S": "system",
        "A": "archivable",
    }
    KEPT_PROPERTIES: ClassVar = {
        "Label",
        "Path",
        "Type",
        "Created",
        "Creator Application",
        "File System",
    }

    REGEX_7ZIP_VERSION: ClassVar = re.compile(
        # 7-Zip (z) 24.09 (x64) : Copyright (c) 1999-2021 Igor Pavlov : 2021-12-26
        r"^7-Zip[^\d]+(\d+\.\d+)",
    )
    REGEX_MODE_PROPERTIES: ClassVar = re.compile(
        # --/----
        r"^(--|----)$",
    )
    REGEX_PROPERTY: ClassVar = re.compile(
        # Comment =
        r"^(.+) = (.+)$",
    )
    REGEX_MODE_FILES: ClassVar = re.compile(
        #    Date      Time    Attr         Size   Compressed  Name
        r"\s+Date\s+Time\s+Attr\s+Size\s+Compressed\s+Name"
    )
    REGEX_FILE: ClassVar = re.compile(
        # 2022-12-05 17:23:59 ....A       100656       102400  lorem.txt
        r"""
        (?P<datetime>\d+-\d+-\d+\s\d+:\d+:\d+)\s+
        (?P<modes>[A-Z.]{5})
        (?:\s+(?P<size>\d+))?
        (?:\s+(?P<compressed>\d+))?\s+
        (?P<name>.+)
        """,
        re.VERBOSE,
    )

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        file_limit = self.evaluate_limit(options.get("limit", -1))
        hash_all_files = options.get("hash_all_files", True)
        tmp_dir = options.get("tmp_file_directory", tempfile.gettempdir())
        sevenzz = self.find_executable("7zz", options.get("7zz"))

        # initialize our event data
        self.event.update(
            {
                "total": {
                    "files": 0,
                    "directories": 0,
                    "extracted": 0,
                },
                "hidden_dirs": [],
                "meta": {
                    "partitions": [],
                },
            }
        )

        # Check if 7zip package is installed
        if sevenzz is None:
            self.add_flag("7zip_not_installed_error")
            return

        # skip the things we want to ignore via 7zz command line flags rather than
        # extracting/listing everything and filtering, should be more efficient
        exclusion_cmdline_args = [
            # exclude any of the given excluded root directories
            *(f"-xm!{n}/" for n in self.EXCLUDED_ROOT_DIRS),
            # also skip some of the extended attributes
            *(f"-xr!*:{e}" for e in self.SKIPPED_EXTATTRS),
        ]

        with (
            tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data,
            tempfile.TemporaryDirectory(dir=tmp_dir) as tmp_extract,
        ):
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            indices = {}

            try:
                result = subprocess.run(
                    [
                        sevenzz,
                        "l",
                        *exclusion_cmdline_args,
                        tmp_data.name,
                    ],
                    capture_output=True,
                    encoding="utf-8",
                    check=True,
                    timeout=self.scanner_timeout,
                )
            except Exception as e:
                self.add_flag("7zip_list_error", e)
            else:
                try:
                    indices.update(
                        self.parse_7zip_stdout(result.stdout, file.name, tmp_data.name)
                    )
                except Exception as e:
                    self.add_flag("7zip_list_parse_error", e)

            try:
                subprocess.run(
                    [
                        sevenzz,
                        "x",
                        *exclusion_cmdline_args,
                        f"-o{tmp_extract}",
                        tmp_data.name,
                    ],
                    capture_output=True,
                    encoding="utf-8",
                    check=True,
                    timeout=self.scanner_timeout,
                )
            except Exception as e:
                self.add_flag("7zip_extract_error", e)

            # iterate over the files that we extracted from the listing
            for index, metadata in indices.values():
                # figure out the actual path to our file, relative to our extracted root
                name = Path(tmp_extract) / metadata["path"]
                child_data = None

                # make sure we're not over our file limit; if we are, we will still
                # output children for those files, but not recurse
                if name.is_dir():
                    metadata["type"] = FileType.directory
                elif name.is_file():
                    metadata["type"] = FileType.file
                    if self.event["total"]["extracted"] >= file_limit:
                        # we won't pass the data along, but we can generate hashes for
                        # it if we are allowed to, since we already have the data...
                        if hash_all_files and name.is_file():
                            metadata["hash"] = Hash.for_data(name.read_bytes())
                        self.add_flag("file_limit_reached")
                    # we haven't reached our file limit yet, and this is a file, so we can
                    # get the file's data for recursing
                    else:
                        child_data = name.read_bytes()
                        self.event["total"]["extracted"] += 1

                # emit a child with our collected data/metadata
                self.emit_file(
                    **metadata,
                    data=child_data,
                    unique_key=(index,),
                )

    @staticmethod
    def parse_7zip_timestamp(ts: str) -> datetime.datetime:
        if "." in ts:
            ts = ts[:ts.rindex(".") + 7]
        else:
            ts = ts + ".000000"
        dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
        return dt.astimezone().astimezone(datetime.UTC)

    def parse_7zip_stdout(
        self,
        output_7zip: str,
        archive: str | None,
        tmp_data: str,
    ) -> dict[str, int]:
        mode = None

        output_lines = output_7zip.splitlines()

        partition = {}
        indices = {}
        counter = count(1)

        for output_line in output_lines:
            if not output_line:
                continue

            # Properties section
            if match := self.REGEX_MODE_PROPERTIES.match(output_line):
                if "path" in partition.keys():
                    if "created" in partition:
                        partition["created"] = self.parse_7zip_timestamp(partition["created"])
                    self.event["meta"]["partitions"].append(partition)
                partition = {}
                mode = "properties"

            # File section
            if match := self.REGEX_MODE_FILES.match(output_line):
                # Wrap up final partition
                if "path" in partition.keys():
                    if "created" in partition:
                        partition["created"] = self.parse_7zip_timestamp(partition["created"])
                    self.event["meta"]["partitions"].append(partition)
                partition = {}
                mode = "files"

            # Header section
            if not mode:
                if match := self.REGEX_7ZIP_VERSION.match(output_line):
                    self.event["meta"]["7zip_version"] = match.group(1)
                    continue

            elif mode == "properties":
                # Collect specific properties
                if match := self.REGEX_PROPERTY.match(output_line):
                    key, value = match.groups()
                    if key not in self.KEPT_PROPERTIES:
                        continue
                    if archive and value == tmp_data:
                        value = archive
                    partition[inflection.underscore(key.replace(" ", ""))] = value

            elif mode == "files":
                if match := self.REGEX_FILE.match(output_line):
                    name = Path(match.group("name"))

                    modes_list = list(
                        filter(
                            bool,
                            map(self.FILE_MODE_MAPPING.get, match.group("modes")),
                        )
                    )

                    # No DMG sample available has a file property of hidden
                    # if "hidden" in modes_list and "directory" in modes_list:
                    #    self.event["hidden_dirs"].append(match.group("name"))

                    metadata = {
                        "size": int(match.group("size") or 0),
                        "mtime": self.parse_7zip_timestamp(
                            match.group("datetime")
                        ),
                        "path": str(name),
                    }
                    if modes_list:
                        metadata["attributes"] = set(modes_list)

                    indices[str(name)] = (next(counter), metadata)

                    if "directory" in modes_list:
                        self.event["total"]["directories"] += 1
                        metadata.pop("size", None)
                    else:
                        self.event["total"]["files"] += 1

        return indices
