import io
import lzma

from . import File, Options, Scanner
from ..model import Date


class ScanLzma(Scanner):
    """Decompresses LZMA files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            with (
                io.BytesIO(data) as data_fh,
                lzma.LZMAFile(filename=data_fh) as lzma_fh,
            ):
                self.emit_file(
                    lzma_fh.read(),
                    name=":lzma-contents",
                )
        except lzma.LZMAError:
            self.add_flag("decompression_error")
        except EOFError:
            self.add_flag("eof_error")
