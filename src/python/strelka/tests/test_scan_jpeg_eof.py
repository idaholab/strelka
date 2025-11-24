from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_jpeg_eof = fixtures.scanners.jpeg_eof
data_jpg = fixtures.data("test.jpg")
data_pe_overlay_jpg = fixtures.data("test_pe_overlay.jpg")


def test_scan_jpeg_no_trailer(
    scan_jpeg_eof: Scanner,
    data_jpg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"jpeg_eof:no_trailer"},
    )
    run_test_scan(
        scanner=scan_jpeg_eof,
        fixture=data_jpg,
        expected=test_event,
    )


def test_scan_jpeg_pe_overlay(
    scan_jpeg_eof: Scanner,
    data_pe_overlay_jpg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "854f7011-67b4-5564-9446-d47f5d3d8d11",
                name=":jpeg-trailer",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                size=4096,
                mime_type={"application/vnd.microsoft.portable-executable"},
            ),
        ],
        scan={
            "trailer_start": 308566,
        },
    )
    run_test_scan(
        scanner=scan_jpeg_eof,
        fixture=data_pe_overlay_jpg,
        expected=test_event,
    )
