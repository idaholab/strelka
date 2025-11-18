import base64
from datetime import UTC
import email
import email.header
import email.message
import html
import logging

import eml_parser

from . import Options, Scanner
from ..model import Date, File
from ..util import unquote
from ..util.collections import get_nested


# Configure logging to suppress warnings for fontTools
fonttools_logger = logging.getLogger("fontTools.subset")
fonttools_logger.setLevel(logging.WARNING)


class ScanEmail(Scanner):
    """
    Extracts and analyzes metadata, attachments, and generates thumbnails from email messages.

    This scanner processes email files to extract and analyze metadata and attachments.
    It supports both plain text and HTML emails, including inline images.

    Scanner Type: Collection

    Attributes:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Document Extraction**
            - Extracts and analyzes documents, including attachments, from email messages for content review.
        - **Email Header Analysis**
            - Analyzes email headers for potential indicators of malicious activity, such as suspicious sender addresses
            or subject lines.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Email Encoding and Complex Structures**
            - Limited support for certain email encodings or complex email structures.
        - **Limited Output**
            - Content is limited to a set amount of characters to prevent excessive output.

    ## To Do
    !!! question "To Do"
        - **Improve Error Handling**:
            - Enhance error handling for edge cases and complex email structures.
        - **Enhance Support for Additional Email Encodings and Content Types**:
            - Expand support for various email encodings and content types to improve scanning accuracy.

    ## References
    !!! quote "References"
        - [Python Email Parsing Documentation](https://docs.python.org/3/library/email.html)

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Ryan O'Horo](https://github.com/ryanohoro)

    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """
        Processes the email, extracts metadata, and attachments.

        Args:
            data (bytes): The raw email data.
            file (strelka.File): File details.
            options (dict): Scanner options.
            expire_at (int): Expiry time of the scan.

        Processes the email to extract metadata and attachments.
        """

        # Parse email contents
        try:
            parsed_eml = self.parse_eml(data)

            # Extract email header information
            header = parsed_eml["header"]
            self.event.update(
                {
                    "total": {
                        "attachments": 0,
                        "attachment_bytes": 0,
                        "extracted": 0,
                    },
                    "subject": header.get("subject", ""),
                    "to": header.get("to", []),
                    "cc": header.get("cc", []),
                    "from": header.get("from", ""),
                    "message_id": unquote(
                        get_nested(header, "header.message-id", [""])[0], "<>"
                    ),
                    "date_utc": (d := header.get("date")) and d.astimezone(UTC),
                    # these two fields have nondeterministic ordering because eml_parser
                    # calls `list(set([...]))` when storing them
                    "received_domain": set(header.get("received_domain", ())),
                    "received_ip": set(header.get("received_ip", ())),
                    "domains": [],
                }
            )

            # Extract body content and domains
            # FIXME[elleste]: this only extracts the final body in the email?
            domains = set()
            for body in parsed_eml.get("body", []):
                if "content_type" in body:
                    if body["content_type"] == "text/plain":
                        if len(body["content"]) <= 200:
                            self.event["body"] = body["content"]
                        else:
                            self.event["body"] = (
                                body["content"][:100] + "..." + body["content"][-100:]
                            )
                else:
                    self.event["body"] = (
                        body["content"][:100] + "..." + body["content"][-100:]
                    )
                if "domain" in body:
                    domains.update(body["domain"])

            # this is handled in eml_parser using a `Counter()` object,
            # which stores its values in a nondeterministic order; this
            # fixes the field so it is deterministic in our event
            self.event["domains"].extend(sorted(domains))

            # Extract attachment details and raw data
            for attachment in parsed_eml.get("attachment", []):
                # try to send attachment contents back to Strelka
                self.event["total"]["attachment_bytes"] += attachment["size"]
                self.event["total"]["attachments"] += 1
                if self.emit_file(
                    base64.b64decode(attachment["raw"]),
                    name=attachment["filename"],
                    mime_type={attachment["mime_type_short"]},
                ):
                    self.event["total"]["extracted"] += 1

        except Exception as e:
            self.add_flag("email_parse_error", e)

    @staticmethod
    def decode_and_format_header(msg: email.message.Message, header_name: str) -> str:
        """
        Decodes and safely formats a specific header field from an email message.

        Email headers can be encoded in various formats. This function decodes the header
        into a human-readable format, and also ensures that the text is safe for HTML display.

        Args:
            msg (email.message.Message): Parsed email message object.
            header_name (str): The name of the header field to decode.

        Returns:
            A string representing the decoded and formatted header field values.
            Returns a placeholder string if the header field is missing or cannot be decoded.

        """
        try:
            # Decode the specified header field
            decoded_header = email.header.decode_header(msg[header_name])[0]
            # Convert bytes to string if necessary
            field_value = decoded_header[0]
            if isinstance(field_value, bytes):
                field_value = field_value.decode(decoded_header[1] or "utf-8")
        except Exception:
            field_value = "<Unknown>"

        # Escape the result for HTML safety
        return html.escape(field_value, quote=True)

    @staticmethod
    def parse_eml(data: bytes) -> dict:
        # Open and parse email byte string
        ep = eml_parser.EmlParser(include_attachment_data=True, include_raw_body=True)
        parsed_eml = ep.decode_email_bytes(data)

        # Check if email was parsed properly and attempt to deconflict and reload.
        if not (parsed_eml["header"]["subject"] and parsed_eml["header"]["header"]):
            if b"\nReceived: from " in data:
                data = (
                    data.rpartition(b"\nReceived: from ")[1]
                    + data.rpartition(b"\nReceived: from ")[2]
                )[1:]
            elif b"Start mail input; end with <CRLF>.<CRLF>\n" in data:
                data = data.rpartition(b"Start mail input; end with <CRLF>.<CRLF>\n")[2]
            parsed_eml = ep.decode_email_bytes(data)

        return parsed_eml
