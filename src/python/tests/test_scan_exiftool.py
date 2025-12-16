import warnings

from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    parse_timestamp,
    run_test_scan,
)
from strelka.util.collections import get_nested


scan_exiftool = fixtures.scanners.exiftool
data_doc = fixtures.data("test.doc")
data_jpg = fixtures.data("test.jpg")
data_msi = fixtures.data("test.msi")


KNOWN_GOOD_VERSIONS = {"12.6", "13.1"}


def check_exiftool_version(result) -> None:
    if not isinstance(result, dict):
        warnings.warn("scanner results not a dictionary?")
        return
    version = get_nested(result, "scan.exiftool_version")
    if version is None:
        warnings.warn("scan results don't contain ExifTool version")
    elif str(version) not in KNOWN_GOOD_VERSIONS:
        warnings.warn(f"possibly unsupported version of ExifTool: {version}")


def test_scan_exiftool_doc(
    scan_exiftool: Scanner,
    data_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "app_version": 16.0,
            "author": "Ryan.OHoro",
            "characters": 2452,
            "char_count_with_spaces": 2877,
            "code_page": "Windows Latin 1 (Western European)",
            "comments": "",
            "company": "Target Corporation",
            "comp_obj_user_type_len": 32,
            "comp_obj_user_type": "Microsoft Word 97-2003 Document",
            "create_date": parse_timestamp("2022-12-16 19:48:00Z"),
            "doc_flags": "Has picture, 1Table, ExtChar",
            "exiftool_version": ...,
            "file_size": "51 kB",
            "file_type": "DOC",
            "file_type_extension": "doc",
            "heading_pairs": "Title, 1",
            "hyperlinks_changed": "No",
            "identification": "Word 8.0",
            "keywords": "",
            "language_code": "English (US)",
            "last_modified_by": "Ryan.OHoro",
            "last_printed": None,
            "lines": 20,
            "links_up_to_date": "No",
            "mime_type": "application/msword",
            "modify_date": parse_timestamp("2022-12-16 19:48:00Z"),
            "pages": 1,
            "paragraphs": 5,
            "revision_number": 2,
            "scale_crop": "No",
            "security": "None",
            "shared_doc": "No",
            "software": "Microsoft Office Word",
            "subject": "",
            "system": "Windows",
            "template": "Normal.dotm",
            "title": "",
            "title_of_parts": "",
            "total_edit_time": "1 minute",
            "word97": "No",
            "words": 430,
        },
    )
    run_test_scan(
        scanner=scan_exiftool,
        fixture=data_doc,
        expected=test_event,
        checks=[check_exiftool_version],
    )


def test_scan_exiftool_jpg(
    scan_exiftool: Scanner,
    data_jpg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "exiftool_version": ...,
            "file_size": "309 kB",
            "file_type": "JPEG",
            "file_type_extension": "jpg",
            "mime_type": "image/jpeg",
            "exif_byte_order": "Little-endian (Intel, II)",
            "orientation": "Horizontal (normal)",
            "x_resolution": 72,
            "y_resolution": 72,
            "resolution_unit": "inches",
            "software": "ACDSee Pro 7",
            "modify_date": parse_timestamp("2021-02-06 19:55:44Z"),
            "ycbcr_positioning": "Centered",
            "sub_sec_time": 903,
            "exif_image_width": 1236,
            "exif_image_height": 891,
            "xmp_toolkit": "Image::ExifTool 12.44",
            "gps_latitude": "22 deg 54' 40.92\" S",
            "gps_longitude": "43 deg 12' 21.30\" W",
            "profile_cmm_type": "Linotronic",
            "profile_version": "2.1.0",
            "profile_class": "Display Device Profile",
            "color_space_data": "RGB ",
            "profile_connection_space": "XYZ ",
            "profile_date_time": parse_timestamp("1998-02-09 06:49:00Z"),
            "profile_file_signature": "acsp",
            "primary_platform": "Microsoft Corporation",
            "cmm_flags": "Not Embedded, Independent",
            "device_manufacturer": "Hewlett-Packard",
            "device_model": "sRGB",
            "device_attributes": "Reflective, Glossy, Positive, Color",
            "rendering_intent": "Perceptual",
            "connection_space_illuminant": "0.9642 1 0.82491",
            "profile_creator": "Hewlett-Packard",
            "profile_id": 0,
            "profile_copyright": "Copyright (c) 1998 Hewlett-Packard Company",
            "profile_description": "sRGB IEC61966-2.1",
            "media_white_point": "0.95045 1 1.08905",
            "media_black_point": "0 0 0",
            "red_matrix_column": "0.43607 0.22249 0.01392",
            "green_matrix_column": "0.38515 0.71687 0.09708",
            "blue_matrix_column": "0.14307 0.06061 0.7141",
            "device_mfg_desc": "IEC http://www.iec.ch",
            "device_model_desc": "IEC 61966-2.1 Default RGB colour space - sRGB",
            "viewing_cond_desc": "Reference Viewing Condition in IEC61966-2.1",
            "viewing_cond_illuminant": "19.6445 20.3718 16.8089",
            "viewing_cond_surround": "3.92889 4.07439 3.36179",
            "viewing_cond_illuminant_type": "D50",
            "luminance": "76.03647 80 87.12462",
            "measurement_observer": "CIE 1931",
            "measurement_backing": "0 0 0",
            "measurement_geometry": "Unknown",
            "measurement_flare": "0.999%",
            "measurement_illuminant": "D65",
            "technology": "Cathode Ray Tube Display",
            "red_trc": ...,
            "green_trc": ...,
            "blue_trc": ...,
            "comment": "Colégio Militar do Rio de Janeiro (J David, 1906)",
            "image_width": 1236,
            "image_height": 891,
            "encoding_process": "Baseline DCT, Huffman coding",
            "bits_per_sample": 8,
            "color_components": 3,
            "ycbcr_sub_sampling": "YCbCr4:2:2 (2 1)",
            "image_size": "1236x891",
            "megapixels": 1.1,
            "sub_sec_modify_date": parse_timestamp("2021-02-06 19:55:44.903Z"),
            "gps_latitude_ref": "South",
            "gps_longitude_ref": "West",
            "gps_position": "22 deg 54' 40.92\" S, 43 deg 12' 21.30\" W",
        },
    )
    run_test_scan(
        scanner=scan_exiftool,
        fixture=data_jpg,
        expected=test_event,
        checks=[check_exiftool_version],
    )


def test_scan_exiftool_msi(
    scan_exiftool: Scanner,
    data_msi: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "exiftool_version": ...,
            "author": "Target",
            "code_page": "Windows Latin 1 (Western European)",
            "comments": "This installer database contains the logic and data "
            "required to install StrelkaMSITest.",
            "create_date": parse_timestamp("2023-08-07 11:59:38Z"),
            "file_size": "33 kB",
            "file_type": "FPX",
            "file_type_extension": "fpx",
            "keywords": "Installer",
            "mime_type": "image/vnd.fpx",
            "modify_date": parse_timestamp("2023-08-07 11:59:38Z"),
            "pages": 200,
            "revision_number": "{3F5D9FF7-E061-48CF-95B2-0AA7C9E5DE2A}",
            "security": "Read-only recommended",
            "software": "Windows Installer XML Toolset (3.11.2.4516)",
            "subject": "StrelkaMSITest",
            "template": "Intel;1033",
            "title": "Installation Database",
            "words": 2,
        },
    )
    run_test_scan(
        scanner=scan_exiftool,
        fixture=data_msi,
        expected=test_event,
        checks=[check_exiftool_version],
    )
