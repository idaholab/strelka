import io

import pyzstd

from . import File, Options, Scanner
from ..model import Date


class ScanZstd(Scanner):
    """Decompresses zstandard-compressed files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            with (
                io.BytesIO(data) as data_fh,
                pyzstd.ZstdFile(data_fh) as zstd_fh,
            ):
                self.emit_file(
                    zstd_fh.read(),
                    name=":zstd-contents",
                )
        except pyzstd.ZstdError:
            self.add_flag("decompression_error")
        except EOFError:
            self.add_flag("eof_error")
