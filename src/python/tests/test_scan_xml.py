from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_xml import ScanXml as ScanUnderTest
from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_child,
    make_event,
    make_indicator,
    run_test_scan,
)


scan_xml = fixtures.scanners.xml
data_xml = fixtures.data("test.xml")
data_external_xml = fixtures.data("test_external.xml")


def test_scan_xml(
    scan_xml: Scanner,
    data_xml: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator("domain-name", "example.com"),
            make_indicator("domain-name", "www.w3.org"),
        ],
        scan={
            "tags": {
                "book",
                "author",
                "price",
                "year",
                "title",
            },
            "tag_data": [
                {
                    "tag": "book",
                    "matched": {"category"},
                    "content": {
                        "category": "science",
                    },
                },
                {
                    "tag": "book",
                    "matched": {"category"},
                    "content": {
                        "category": "science",
                    },
                },
            ],
            "namespaces": {
                "http://example.com/books",
            },
            "total": {
                "extracted": 0,
            },
            "doc_type": '<!DOCTYPE bookstore SYSTEM "bookstore.dtd">',
            "version": "1.0",
        },
    )
    run_test_scan(
        scanner=scan_xml,
        fixture=data_xml,
        options={
            "extract_tags": ["Data"],
            "metadata_tags": ["category"],
        },
        expected=test_event,
    )


def test_scan_xml_content_extraction(
    scan_xml: Scanner,
    data_external_xml: File,
) -> None:
    """
    Pass:   Sample event matched output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "c71eba9c-d7a1-5f89-b1e2-20ee6481819e",
                sha1="419b05b36ae786712fadce183c032ec3786eb884",
                mime_type={"text/plain"},
                name=":data",
                size=116,
            ),
            make_child(
                "1b797f4f-cbf9-5f05-9ebe-c49859d71e16",
                sha1="ef1071d7677f4566abddd557c742d4f231b2de8c",
                mime_type={"text/plain"},
                name=":script",
                size=93,
            ),
        ],
        related=[
            make_indicator("domain-name", "ftp.example.com"),
            make_indicator("domain-name", "schemas.openxmlformats.org"),
            make_indicator("domain-name", "www.example.com"),
            make_indicator("domain-name", "www.w3.org"),
            make_indicator("ipv4-addr", "127.0.0.1"),
        ],
        scan={
            "tags": {
                "canonicalizationmethod",
                "cipherdata",
                "ciphervalue",
                "data",
                "digestmethod",
                "digestvalue",
                "embeddedfile",
                "encrypteddata",
                "encryptionmethod",
                "reference",
                "relationship",
                "relationships",
                "script",
                "signaturemethod",
                "signedinfo",
            },
            "tag_data": [
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId1",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                        "Target": "../media/image1.png",
                    },
                },
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId3",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                        "Target": "../media/image2.png",
                    },
                },
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId2",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": r"file:///\\\\127.0.0.1\\share\\EXCEL_OPEN_DOCUMENT.vbs",
                        "TargetMode": "External",
                    },
                },
                {
                    "tag": "embeddedfile",
                    "matched": {"type"},
                    "content": {
                        "Id": "file1",
                        "Type": "image/png",
                    },
                },
                {
                    "tag": "encrypteddata",
                    "matched": {"type"},
                    "content": {
                        "Id": "encData1",
                        "Type": "http://www.w3.org/2001/04/xmlenc#Element",
                    },
                },
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId4",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "https://www.example.com",
                        "TargetMode": "External",
                    },
                },
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId5",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "mailto:user@example.com",
                        "TargetMode": "External",
                    },
                },
                {
                    "tag": "relationship",
                    "matched": {"type"},
                    "content": {
                        "Id": "rId6",
                        "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                        "Target": "ftp://ftp.example.com/resource",
                        "TargetMode": "External",
                    },
                },
            ],
            "namespaces": {
                "http://schemas.openxmlformats.org/package/2006/relationships",
            },
            "total": {
                "extracted": 2,
            },
            "doc_type": '<!DOCTYPE Relationships SYSTEM "relationships.dtd">',
            "version": "1.0",
        },
    )
    run_test_scan(
        scanner=scan_xml,
        fixture=data_external_xml,
        options={
            "extract_tags": [
                "target",
                "script",
                "embeddedfile",
                "cipherdata",
                "data",
                "signedinfo",
                "encrypteddata",
            ],
            "metadata_tags": [
                "type",
            ],
        },
        expected=test_event,
    )
