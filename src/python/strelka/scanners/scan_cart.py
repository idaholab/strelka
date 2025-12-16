import io

import cart

from . import File, Options, Scanner
from ..model import Date


class ScanCart(Scanner):
    """Decompresses CaRT archives."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        arc4_key = options.get("arc4_key", cart.DEFAULT_ARC4_KEY)

        try:
            with (
                io.BytesIO(data) as data_fh,
                io.BytesIO() as cart_fh,
            ):
                # unpack the cart, then extract our filename from the metadata
                metadata, _ = cart.unpack_stream(data_fh, cart_fh, arc4_key)
                name = metadata.pop("name", ":cart-contents")
                # emit a child with the name we extracted, using the remaining metadata
                # as the child's metadata
                self.emit_file(
                    cart_fh.getbuffer(),
                    name=name,
                    metadata=metadata,
                )
        except cart.InvalidARC4KeyException:
            self.add_flag("invalid_arc4_key")
        except cart.InvalidCARTException:
            self.add_flag("invalid_file")
        except EOFError:
            self.add_flag("eof_error")
