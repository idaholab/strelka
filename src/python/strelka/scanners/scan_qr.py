import io
import logging

from PIL import Image, ImageOps
from pyzbar.pyzbar import decode

from . import Scanner

logging.getLogger("PIL").setLevel(logging.WARNING)


class ScanQr(Scanner):
    """
    Collects QR code metadata from image files.
    """

    def scan(self, data, file, options, expire_at):
        support_inverted = options.get("support_inverted", True)

        self.event["data"] = []

        barcode_data = []

        try:
            img = Image.open(io.BytesIO(data))
            if img.mode == "P":
                img = img.convert("RGBA")  # Convert palette to RGBA
            barcodes = decode(img)

            if barcodes:
                for barcode in barcodes:
                    barcode_data.append(barcode.data.decode("utf-8"))

            if support_inverted:
                img_inverted = ImageOps.invert(img)
                barcodes = decode(img_inverted)

                if barcodes:
                    self.flags.append("inverted")
                    for barcode in barcodes:
                        barcode_data.append(barcode.data.decode("utf-8"))

            if barcode_data:
                self.event["data"] = barcode_data

        except Exception:
            self.flags.append("decode_error")
