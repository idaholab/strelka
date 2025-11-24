import gzip
import io
import zlib

from . import File, Options, Scanner
from ..model import Date


class ScanGzip(Scanner):
    """Decompresses gzip files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            with (
                io.BytesIO(data) as data_fh,
                gzip.GzipFile(fileobj=data_fh) as gzip_fh,
            ):
                self.emit_file(
                    gzip_fh.read(),
                    name=":gzip-contents",
                )
        except (gzip.BadGzipFile, zlib.error):
            self.add_flag("decompression_error")
        except EOFError:
            self.add_flag("eof_error")
