import zlib

from . import File, Options, Scanner


class ScanZlib(Scanner):
    """Decompresses zlib files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: float) -> None:
        try:
            decompressed = zlib.decompress(data)
            self.event["size"] = len(decompressed)
            self.emit_file(
                decompressed,
                name=file.name or "zlib-contents",
            )
        except zlib.error:
            self.add_flag("bad_zlib_data")
        except EOFError:
            self.add_flag("eof_error")
