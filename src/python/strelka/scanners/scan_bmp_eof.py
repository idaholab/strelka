from . import File, Options, Scanner
from ..model import Date


class ScanBmpEof(Scanner):
    """
    Take the data of the BMP image, parse it, and determine if data is stored beyond
    the expected end of file.
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        expected_size = int.from_bytes(data[2:6], "little")
        if expected_size != len(data):
            self.event["trailer_start"] = expected_size
            self.emit_file(
                data[expected_size:],
                name=":bmp-trailer",
            )
        else:
            self.add_flag("no_trailer")
