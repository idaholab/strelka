from typing import Any, Dict

from lxml import etree

from . import Options, Scanner
from ..auxiliary.indicators import extract_indicators_from_string
from ..model import Date, File


class ScanXml(Scanner):
    """
    Collects metadata and extracts embedded files from XML files.

    This scanner parses XML files to collect metadata and extract embedded files based on specified tags.
    It is used in forensic and malware analysis to extract and analyze structured data within XML documents.

    Scanner Type: Collection

    Attributes:
        None

    Options:
        extract_tags (list[str]): Tags whose content is extracted as child files.
        metadata_tags (list[str]): Tags whose content is logged as metadata.

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Embedded File Extraction**
            - Extracts files embedded within specific XML tags.
        - **Metadata Extraction**:
            - Collects metadata from specific XML tags.

    ## Known Limitations
    !!! warning "Known Limitations"
        - Complex or malformed XML structures might lead to incomplete parsing or errors.
        - Excessive files may be scanned / collected if XML mimetypes are set in the `backend.yml`

    ## To Do
    !!! question "To Do"
        - Improve error handling for malformed XML structures.
        - Better extraction of tags / metadata tags

    ## References
    !!! quote "References"
        - XML File Format Specification (https://www.w3.org/XML/)

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """
        Parses XML data to extract metadata and files.

        Args:
            data: XML data as bytes.
            file: File object containing metadata about the scan.
            options: Dictionary of scanner options.
            expire_at: Time when the scan should be considered expired.

        Scans the XML file, extracting data and metadata based on the specified tags,
        and emits files as necessary.

        If given file is not a XML file, then the scanner will append a flag denoting this and exit
        """

        # Prepare options with case-insensitive tag matching
        xml_options = {
            "extract_tags": {tag.lower() for tag in options.get("extract_tags", [])},
            "metadata_tags": {tag.lower() for tag in options.get("metadata_tags", [])},
        }

        # Initialize scan event data
        self.event.update(
            {
                "total": {
                    "extracted": 0,
                },
                "doc_type": None,
                "version": None,
                "tags": set(),
                "tag_data": [],
                "namespaces": set(),
            }
        )

        # Parse the XML content
        try:
            xml_buffer = data
            if xml_buffer.startswith(b"<?XML"):
                xml_buffer = b"<?xml" + xml_buffer[5:]
            xml = etree.fromstring(xml_buffer)
            # Extract and add Indicators of Compromise (IOCs)
            self.add_related(extract_indicators_from_string(etree.tostring(xml, encoding="unicode", method="text")))
            docinfo = xml.getroottree().docinfo
            self.event["doc_type"] = docinfo.doctype if docinfo.doctype else ""
            self.event["version"] = docinfo.xml_version if docinfo.xml_version else ""
            # Recursively process each node in the XML
            self._recurse_node(xml, xml_options)
        except Exception:
            self.fail("parse_failure")

    def _recurse_node(self, node: etree._Element, xml_options: Dict[str, Any]) -> None:
        """
        Recursively processes each XML node to extract data and metadata.

        Args:
            node: The current XML node to process.
            xml_options: Options for data extraction and metadata logging.

        Iterates through XML nodes, extracting data and collecting metadata as specified
        by the scanner options.
        """
        if node is not None and hasattr(node.tag, "__getitem__"):
            namespace, _, tag = node.tag.partition("}")
            namespace = namespace[1:] if namespace.startswith("{") else ""
            tag = tag.lower()

            if tag:
                self.event["tags"].add(tag)
            if namespace:
                self.event["namespaces"].add(namespace)

            # Handle specific content extraction and emission
            if tag in xml_options["extract_tags"]:
                if content := node.text and node.text.strip():
                    self.emit_file(content.encode(), name=f":{tag}")
                    self.event["total"]["extracted"] += 1

            # Check attributes in order to capture any relevant metadata
            attrs = {n.lower() for n in node.attrib}
            if m := {tag, *attrs} & xml_options["metadata_tags"]:
                self.event["tag_data"].append(
                    {
                        "tag": tag,
                        "matched": m,
                        "content": dict(node.attrib),
                    }
                )

            # Continue to recurse through child nodes to extract data
            for child in node.getchildren():
                self._recurse_node(child, xml_options)
