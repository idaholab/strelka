import bz2
import io

from . import File, Options, Scanner
from ..model import Date


class ScanBzip2(Scanner):
    """Decompresses bzip2 files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            with (
                io.BytesIO(data) as data_fh,
                bz2.BZ2File(filename=data_fh) as bzip2_fh,
            ):
                self.emit_file(
                    bzip2_fh.read(),
                    name=":bzip2-contents",
                )
        except EOFError:
            self.add_flag("eof_error")
        except OSError:
            self.add_flag("os_error")
