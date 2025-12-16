import io
import logging

import pillow_avif
from PIL import Image, UnidentifiedImageError
from pillow_heif import register_heif_opener

from . import File, Options, Scanner

logging.getLogger("PIL").setLevel(logging.WARNING)

# Must be imported as a plugin, doesn't need to be used
_ = pillow_avif.AvifImagePlugin

register_heif_opener()


class ScanTranscode(Scanner):
    """
    Converts supported images for easier scanning

    Typical supported output options:
    gif webp jpeg bmp png tiff

    Scanner Type: Collection

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Image Extraction**
            - This scanner converts image types into a version that is able to be processed by tesseract in ScanOCR.

    ## Contributors
    !!! example "Contributors"
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at) -> None:
        output_format = options.get("output_format", "jpeg")

        def convert(im):
            with io.BytesIO() as f:
                fmt = output_format.lower()

                # JPEG cannot handle alpha channels
                if fmt in ("jpg", "jpeg") and im.mode in ("RGBA", "LA", "P"):
                    im = im.convert("RGB")

                im.save(f, format=output_format, quality=90)
                return f.getvalue()

        try:
            converted_image = convert(Image.open(io.BytesIO(data)))

            # Send extracted file back to Strelka
            self.emit_file(converted_image, name=file.name)
        except UnidentifiedImageError:
            self.flags.append("unidentified_image")
            return

        self.flags.append("transcoded")
