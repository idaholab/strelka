import io

from . import Options, Scanner
from ..auxiliary import xar
from ..model import Date, File, FileType


class ScanXar(Scanner):
    """
    Extract files from XAR archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to unlimited.
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        file_limit = self.evaluate_limit(options.get("limit", -1))

        self.event["total"] = {
            "files": 0,
            "directories": 0,
            "other": 0,
            "extracted": 0,
        }

        try:
            with (
                self.new_temporary_file(data, named=True) as data_fh,
                xar.XarArchive(data_fh.name) as archive,
            ):
                for entry in archive:
                    metadata: dict = {
                        "path": entry.name,
                        "type": FileType.unknown,
                        "uid": entry.uid,
                        "owner": entry.uname,
                        "gid": entry.gid,
                        "group": entry.gname,
                        "mode": entry.mode,
                        "mtime": entry.mtime,
                    }
                    entry.uid
                    child_data = None

                    if entry.isdir():
                        metadata.update(
                            {
                                "type": FileType.directory,
                            }
                        )
                        self.event["total"]["directories"] += 1
                    elif entry.isfile():
                        metadata.update(
                            {
                                "type": FileType.file,
                                "size": entry.size,
                            }
                        )
                        self.event["total"]["files"] += 1
                        if self.event["total"]["extracted"] >= file_limit:
                            self.add_flag("file_limit_reached")
                        # we haven't reached our file limit yet, and this is a file, so
                        # we can get the file's data for recursing
                        else:
                            with io.BytesIO() as file_data:
                                for block in entry.get_blocks():
                                    file_data.write(block)
                                child_data = file_data.getvalue()
                            self.event["total"]["extracted"] += 1
                    else:
                        self.event["total"]["other"] += 1
                        if entry.islnk():
                            metadata.update(
                                {
                                    "type": FileType.hard_link,
                                    "target_path": entry.linkname,
                                }
                            )
                        elif entry.issym():
                            metadata.update(
                                {
                                    "type": FileType.symlink,
                                    "target_path": entry.linkname,
                                }
                            )

                    # emit a child with our collected data/metadata
                    self.emit_file(
                        **metadata,
                        data=child_data,
                    )

        except xar.XarError:
            self.add_flag("archive_error")
