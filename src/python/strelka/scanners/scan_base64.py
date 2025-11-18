import base64
import binascii

from . import File, Options, Scanner
from ..model import Date


class ScanBase64(Scanner):
    """Decodes base64-encoded file."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        try:
            extract_data = base64.b64decode(data)
        except binascii.Error:
            self.add_flag("invalid_data")
        else:
            self.event["decoded_header"] = extract_data[:50]
            self.emit_file(
                extract_data,
                name=":base64-decoded",
            )
