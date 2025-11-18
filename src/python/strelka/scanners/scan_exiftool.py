import datetime
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import ClassVar, Final, Iterable, Literal, overload

from . import Options, Scanner
from ..model import Date, File


timestamp_re: Final = re.compile(
    r"^\d{4}:\d{2}:\d{2}"
    r"(\s+|T)"
    r"\d{2}:\d{2}:\d{2}(\.\d+)?"
    r"(Z|[-+]\d{2}(:?\d{2})?)?$"
)


MetadataScalar = str | int | float | bool | None | datetime.datetime


class ScanExiftool(Scanner):
    """Collects metadata parsed by Exiftool.

    This scanner uses Exiftool to extract metadata from files and logs the
    extracted key-value pairs.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to the system temp directory.
    """

    # don't include any of these keys when parsing the JSON output from exiftool; they
    # are tied to the filesystem, and since we're using a temporary file, they are
    # completely meaningless
    EXCLUDED_KEYS: ClassVar = {
        "directory",
        "file_name",
        "source_file",
        "file_access_date",
        "file_inode_change_date",
        "file_modify_date",
        "file_permissions",
    }
    # these are "words" that should be treated as a single unit when converting from
    # camelcase -> underscore, since we can't automatically handle them due to caps
    WORDS: ClassVar = {
        "ExifTool",
        "MIME",
        "XMP",
        "GPS",
        "CMM",
        "ID",
        "TRC",
        "YCbCr",
    }

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        tmp_directory = options.get("tmp_directory", tempfile.gettempdir())

        # Use a temporary file to store the data for processing with Exiftool
        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            self.event.update(self.run_exiftool(tmp_data.name))

    @overload
    def run_exiftool(
        self,
        file: str | Path,
        *,
        merge_lists: Literal[False],
        exiftool_args: Iterable[str] = (),
        excluded: set[str] | None = None,
        included: set[str] | None = None,
        words: set[str] | None = None,
        convert_timestamps: bool = True,
    ) -> dict[str, MetadataScalar | list]: ...

    @overload
    def run_exiftool(
        self,
        file: str | Path,
        *,
        merge_lists: Literal[True] = True,
        exiftool_args: Iterable[str] = (),
        excluded: set[str] | None = None,
        included: set[str] | None = None,
        words: set[str] | None = None,
        convert_timestamps: bool = True,
    ) -> dict[str, MetadataScalar]: ...

    def run_exiftool(
        self,
        file: str | Path,
        *,
        exiftool_args: Iterable[str] = (),
        excluded: set[str] | None = None,
        included: set[str] | None = None,
        words: set[str] | None = None,
        merge_lists: bool = True,
        convert_timestamps: bool = True,
    ) -> dict[str, MetadataScalar] | dict[str, MetadataScalar | list]:
        if excluded is None:
            excluded = self.EXCLUDED_KEYS
        if words is None:
            words = self.WORDS

        try:
            # Execute exiftool and retrieve JSON metadata output
            result = subprocess.run(
                ["exiftool", "-j", *exiftool_args, str(file)],
                encoding="utf-8",
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            self.add_flag("exiftool_subprocess_error")
            return {}

        try:
            raw_metadata = json.loads(result.stdout or "[{}]")[0]
        except json.JSONDecodeError:
            self.add_flag("exiftool_json_error")
            return {}

        metadata = {}
        for key, value in raw_metadata.items():
            key = self.normalize_key(key, words=words)
            if (included and key not in included) or key in excluded:
                continue
            if merge_lists and isinstance(value, list):
                value = ", ".join(map(str, value))
            if convert_timestamps and self.is_timestamp(value):
                try:
                    value = self.parse_timestamp(value)
                except ValueError:
                    self.add_flag("invalid_timestamp_format")
            metadata[key] = value

        return metadata

    @staticmethod
    def is_timestamp(value: str) -> bool:
        return bool(isinstance(value, str) and timestamp_re.match(value))

    @staticmethod
    def parse_timestamp(ts: str) -> datetime.datetime | None:
        # this is the "null value", which is invalid, so just return None if that's the
        # case, since we can't exactly represent it using a datetime object
        if ts == "0000:00:00 00:00:00":
            return None
        # exiftool uses weird timestamps with ':' as the date component separator; we
        # also can't actually determine timezone if it isn't specified as part of the
        # timestamp, since it's generally a string
        dt = datetime.datetime.fromisoformat(ts.replace(":", "-", 2))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        else:
            dt = dt.astimezone(datetime.UTC)
        return dt
