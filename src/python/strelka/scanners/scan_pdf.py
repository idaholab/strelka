import binascii
from collections import Counter
from datetime import datetime, timezone
import io
import re

import pymupdf

from . import Options, Scanner
from ..model import Date, File
from ..auxiliary import indicators


# Suppress PyMuPDF warnings
pymupdf.TOOLS.mupdf_display_errors(False)

# Regular expression for extracting phone numbers from PDFs
PHONE_NUMBERS_REGEX = re.compile(
    r"(?:[+]?(\d{1,3})[\s.-]?)?"  # optional country code
    r"(?:\((\d{3})\)|(\d{3}))[\s.-]?"  # area code, possibly in parens
    r"(\d{3})(?:[\s.-]?(\d{2,4}))?"  # subscriber number
    r"(?:[-#]?(\d{2,4}))?"  # optional extension
)


class ScanPdf(Scanner):
    """
    Extracts metadata, embedded files, images, and text from PDF files.

    This scanner utilizes PyMuPDF to parse PDF files, extracting various types of data,
    including metadata, embedded files, images, and textual content. Phone numbers and
    URLs within the document are also extracted and reported.
    """

    @staticmethod
    def _convert_timestamp(timestamp: str) -> datetime | None:
        """
        Converts a PDF timestamp string to an ISO 8601 formatted string.

        PDF timestamps are typically in the 'D:%Y%m%d%H%M%S%z' format. This function
        converts them to a more standard ISO 8601 format.

        Args:
            timestamp: A string representing the timestamp in PDF format.

        Returns:
            A datetime object, or None if conversion fails.
        """
        try:
            timestamp = timestamp.replace("'", "")
            # there are nonstandard timestamps that lack a timezone offset; per the
            # PDF spec, these are to be treated as being GMT/UTC
            if not ("+" in timestamp or "-" in timestamp):
                timestamp += "Z"
            return datetime.strptime(timestamp, "D:%Y%m%d%H%M%S%z").astimezone(
                timezone.utc
            )
        except Exception:
            return None

    @classmethod
    def embfile_info(cls, doc: pymupdf.Document, item: int) -> dict:
        idx = doc._embeddedFileIndex(item)
        infodict = {"name": doc.embfile_names()[idx]}
        xref = doc._embfile_info(idx, infodict)
        t, date = doc.xref_get_key(xref, "Params/CreationDate")
        if t != "null":
            infodict["creationDate"] = cls._convert_timestamp(date)
        t, date = doc.xref_get_key(xref, "Params/ModDate")
        if t != "null":
            infodict["modDate"] = cls._convert_timestamp(date)
        t, md5 = doc.xref_get_key(xref, "Params/CheckSum")
        if t != "null":
            try:
                infodict["checksum"] = binascii.hexlify(md5.encode()).decode()
            except UnicodeEncodeError:
                pass
        return infodict

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """
        Performs the scanning process on the provided data.

        The function opens the PDF using PyMuPDF and extracts metadata, embedded files,
        images, and text. Phone numbers and URLs are also extracted using regular
        expressions.

        Args:
            data: Data of the file to be scanned.
            file: The File object associated with the data.
            options: Dictionary of scanner-specific options.
            expire_at: Expiration time of the scan.
        """
        # get the maximum XREF objects to be collected (default: unlimited)
        max_objects = options.get("max_objects", -1)
        # get any specific objects we should be keeping track of
        objects = set(options.get("objects", []))

        if objects:
            object_expr = re.compile(
                "/({})".format("|".join(map(re.escape, objects))), re.I
            )
        else:
            object_expr = None

        with (
            io.BytesIO(data) as pdf_io,
            pymupdf.open(stream=pdf_io, filetype="pdf") as reader,
        ):
            # Collect Metadata
            self.event.update(
                {
                    "total": {
                        "embedded_files": reader.embfile_count(),
                        "images": 0,
                        "lines": 0,
                        "words": 0,
                        "pages": reader.page_count,
                        "xrefs": reader.xref_length() - 1,
                    },
                    "metadata": {
                        "dirty": reader.is_dirty,
                        "encrypted": reader.is_encrypted,
                        "language": reader.language,
                        "needs_pass": reader.needs_pass,
                        # "old_xrefs": reader.has_old_style_xrefs,
                        "repaired": reader.is_repaired,
                    },
                    "urls": set(),
                    "domains": set(),
                    "phones": set(),
                    "xref_objects": set(),
                    "objects": Counter(),
                }
            )

            if reader.is_encrypted:
                return

            if reader.metadata:
                self.event["metadata"].update(
                    {
                        "author": reader.metadata["author"],
                        "creator": reader.metadata["creator"],
                        "creation_date": self._convert_timestamp(
                            reader.metadata["creationDate"]
                        ),
                        "format": reader.metadata["format"],
                        "keywords": reader.metadata["keywords"],
                        "modify_date": self._convert_timestamp(
                            reader.metadata["modDate"]
                        ),
                        "producer": reader.metadata["producer"],
                        "subject": reader.metadata["subject"],
                        "title": reader.metadata["title"],
                    }
                )

            # collect phone numbers
            self.event["phones"].update(
                "+{}".format("".join(x))
                for x in PHONE_NUMBERS_REGEX.findall(
                    " ".join(
                        page.get_textpage().extractText() for page in reader.pages()
                    )
                    .replace("\t", " ")
                    .replace("\n", " ")
                )
            )

            # iterate through xref objects. Collect, count, and extract objects
            for i in range(1, reader.xref_length()):
                xref = reader.xref_object(i, compressed=True)
                if max_objects < 0 or len(self.event["xref_objects"]) < max_objects:
                    self.event["xref_objects"].add(xref)
                if object_expr:
                    for obj in object_expr.findall(xref):
                        self.event["objects"][obj.lower()] += 1
                # extract urls from xref
                self.event["urls"].update(indicators.uri.findall(xref))

            # submit embedded files to strelka
            for i in range(reader.embfile_count()):
                try:
                    props = self.embfile_info(reader, i)
                    self.emit_file(
                        reader.embfile_get(i),
                        name=props.get("filename", f":embedded_file_{i}"),
                        unique_key=("embedded_file", i),
                        created=props.get("creationDate"),
                        mtime=props.get("modDate"),
                        metadata={"pdf:description": props.get("description")},
                    )
                except Exception:
                    self.add_flag("pdf_embedded_processing_error")

            # Submit extracted images to strelka
            for page in reader.pages():
                for img in page.get_images():
                    try:
                        self.event["total"]["images"] += 1
                        pix = pymupdf.Pixmap(reader, img[0])
                        self.emit_file(
                            pix.tobytes(),
                            name=f":image_{img[0]}",
                            unique_key=("image", img[0]),
                        )
                    except Exception:
                        self.add_flag("pdf_image_processing_error")

            # parse the text from each page to generate totals and extract IOCs
            with io.StringIO() as text:
                for page in reader:
                    try:
                        # extract any defined links from the page (n.b. this method
                        # isn't explicitly provided as part of the pymupdf.Page
                        # class, so we have to ignore the typing error)
                        links = page.get_links()  # type: ignore
                        # get this page's text
                        page_text = page.get_textpage().extractText()
                        # extract lines/words from the page
                        lines = list(filter(None, page_text.split("\n")))
                        words = list(filter(None, re.split(r"\s+", page_text)))

                        # add counts to our totals
                        self.event["total"]["lines"] += len(lines)
                        self.event["total"]["words"] += len(words)
                        # add any links that were found
                        self.event["urls"].update(e.get("uri") for e in links)
                        # add this page's text to the combined buffer
                        text.write(page_text)
                    except Exception:
                        self.add_flag("pdf_page_processing_error")

                # also extract any domains from the combined text content
                self.event["domains"].update(
                    indicators.extract_domains(text.getvalue())
                )

                # send the document text content back for further processing
                self.emit_file(
                    text.getvalue().encode(),
                    name=":text-content",
                    unique_key=("text",),
                )

            # clean up the set of links so we don't have useless entries
            self.event["urls"] -= {None}

            # add any urls/domains we found as IOCs
            self.add_related([*self.event["urls"], *self.event["domains"]])
