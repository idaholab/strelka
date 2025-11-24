import collections
import datetime
import io

from pycdlib.dates import DirectoryRecordDate, VolumeDescriptorDate
import pycdlib.pycdlib

from . import Options, Scanner
from ..model import Date, File, FileType


class ScanIso(Scanner):
    """Extracts files from ISO files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        file_limit = self.evaluate_limit(options.get("limit", -1))

        self.event.update(
            {
                "total": {
                    "directories": 0,
                    "files": 0,
                    "extracted": 0,
                },
                "meta": {
                    "date_created": None,
                    "date_effective": None,
                    "date_expiration": None,
                    "date_modification": None,
                    "volume_identifier": None,
                    "raw_volume_identifier": None,
                    "format": None,
                },
            }
        )

        try:
            # ISO must be opened as a byte stream
            with io.BytesIO(data) as iso_io:
                iso = pycdlib.pycdlib.PyCdlib()
                iso.open_fp(iso_io)

                # Attempt to get Meta
                vol_id = (iso.pvd.volume_identifier or b"").decode()
                if iso.has_udf():
                    pathname = "udf_path"
                    iso_format = "udf"
                elif iso.has_rock_ridge():
                    pathname = "rr_path"
                    iso_format = "rockridge"
                elif iso.has_joliet():
                    pathname = "joliet_path"
                    iso_format = "joliet"
                else:
                    pathname = "iso_path"
                    iso_format = "iso"

                self.event["meta"].update(
                    {
                        "format": iso_format,
                        "date_created": self._convert_vol_date(
                            iso.pvd.volume_creation_date
                        ),
                        "date_effective": self._convert_vol_date(
                            iso.pvd.volume_effective_date
                        ),
                        "date_expiration": self._convert_vol_date(
                            iso.pvd.volume_expiration_date
                        ),
                        "date_modification": self._convert_vol_date(
                            iso.pvd.volume_modification_date
                        ),
                        "raw_volume_identifier": vol_id,
                        "volume_identifier": vol_id.rstrip(" "),
                    }
                )

                root_entry = iso.get_record(**{pathname: "/"})

                # Iterate through ISO file tree
                dirs = collections.deque([root_entry])
                while dirs:
                    dir_record = dirs.popleft()
                    ident_to_here = iso.full_path_from_dirrecord(
                        dir_record,
                        rockridge=(pathname == "rr_path"),
                    )

                    attrs = set()
                    file_type = FileType.file
                    file_data = None
                    mtime = None

                    if dir_record.is_dir():
                        self.event["total"]["directories"] += 1

                        file_type = FileType.directory
                        mtime = self._convert_dir_date(dir_record.date)

                        # Try to get hidden files, not applicable to all iso types
                        if getattr(dir_record, "file_flags", None) == 3:
                            attrs.add("hidden")

                        child_lister = iso.list_children(**{pathname: ident_to_here})
                        for child in child_lister:
                            if child is None or child.is_dot() or child.is_dotdot():
                                continue
                            dirs.append(child)

                    else:
                        self.event["total"]["files"] += 1

                        try:
                            record = iso.get_record(**{pathname: ident_to_here})
                        except Exception:
                            self.add_flag("iso_read_error")

                        else:
                            mtime = self._convert_dir_date(record.date)
                            # extract file contents, if below limit
                            if self.event["total"]["extracted"] < file_limit:
                                with io.BytesIO() as file_io:
                                    try:
                                        iso.get_file_from_iso_fp(
                                            file_io, **{pathname: ident_to_here}
                                        )
                                    except Exception:
                                        self.add_flag("iso_extract_error")
                                    else:
                                        file_io.seek(0)
                                        file_data = file_io.read()
                                        self.event["total"]["extracted"] += 1

                    self.emit_file(
                        file_data,
                        path=ident_to_here,
                        attrs=attrs,
                        mtime=mtime,
                        type=file_type,
                    )

                iso.close()
        except Exception:
            self.add_flag("iso_read_error")

    @staticmethod
    def _convert_vol_date(
        volume_date: VolumeDescriptorDate | None,
    ) -> datetime.datetime | None:
        """Convert volume descriptor timestamp to datetime object."""
        if not isinstance(volume_date, VolumeDescriptorDate):
            return
        try:
            return datetime.datetime(
                year=volume_date.year,
                month=volume_date.month,
                day=volume_date.dayofmonth,
                hour=volume_date.hour,
                minute=volume_date.minute,
                second=volume_date.second,
                microsecond=(volume_date.hundredthsofsecond * 10000),
                tzinfo=datetime.timezone(
                    volume_date.gmtoffset * datetime.timedelta(minutes=15)
                ),
            ).astimezone(datetime.UTC)
        except Exception:
            return

    @staticmethod
    def _convert_dir_date(
        iso_date: DirectoryRecordDate | None,
    ) -> datetime.datetime | None:
        """Convert directory record timestamp to datetime object."""
        if not isinstance(iso_date, DirectoryRecordDate):
            return
        try:
            # FIXME[elleste]: this logically makes no sense; is there a MWE that shows
            #                 an ISO that has a date like this?
            # year = 1900 + iso_date.years_since_1900
            # if year < 1970:
            #     year += 100
            return datetime.datetime(
                year=(iso_date.years_since_1900 + 1900),
                month=max(1, iso_date.month),
                day=iso_date.day_of_month,
                hour=iso_date.hour,
                minute=iso_date.minute,
                second=iso_date.second,
                tzinfo=datetime.timezone(
                    iso_date.gmtoffset * datetime.timedelta(minutes=15)
                ),
            ).astimezone(datetime.UTC)
        except Exception:
            return
