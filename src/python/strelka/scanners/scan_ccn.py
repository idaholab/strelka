import itertools
import re

from . import File, Options, Scanner


# RE_AMEX = re.compile(rb"[^0-9](3[47][0-9]{13})[^0-9]")
# RE_DISC = re.compile(rb"[^0-9](6[0-9]{15})[^0-9]")
# RE_MAST = re.compile(rb"[^0-9](5[1-5]{1}[0-9]{14})[^0-9]")
RE_VISA = re.compile(rb"[^0-9](4[0-9]{15})[^0-9]")


class ScanCcn(Scanner):
    """Decodes base64-encoded file."""

    @staticmethod
    def luhn_checksum(card_number: str) -> int:
        return (
            sum(
                itertools.chain(
                    map(int, card_number[1::2]),
                    [sum(map(int, str(d * 2))) for d in map(int, card_number[0::2])],
                )
            )
            % 10
        )

    def is_luhn_valid(self, card_number: str) -> bool:
        return self.luhn_checksum(card_number) == 0

    def scan(self, data: bytes, file: File, options: Options, expire_at: float) -> None:
        for match in RE_VISA.findall(data):
            if self.is_luhn_valid(match.decode()):
                self.add_flag("luhn_match")
