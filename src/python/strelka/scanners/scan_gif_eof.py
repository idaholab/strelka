from . import Scanner, File, Options
from ..model import Date
from ..auxiliary import gif


class ScanGifEof(Scanner):
    """Extracts data embedded in GIF files.

    This scanner extracts data that is inserted past the GIF trailer.
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            parsed_gif = gif.GIF.parse(data)

        except (ValueError, EOFError):
            self.add_flag("gif_parse_error")

        else:
            if len(data) > (start := parsed_gif.total_size):
                self.event["trailer_start"] = start
                self.emit_file(
                    data[start:],
                    name=":gif-trailer",
                )
            else:
                self.add_flag("no_trailer")
