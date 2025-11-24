from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_png_eof = fixtures.scanners.png_eof
data_png = fixtures.data("test.png")
data_pe_overlay_png = fixtures.data("test_pe_overlay.png")
data_broken_iend_png = fixtures.data("test_broken_iend.png")


def test_scan_png_eof_no_trailer(
    scan_png_eof: Scanner,
    data_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"png_eof:no_trailer"},
    )
    run_test_scan(
        scanner=scan_png_eof,
        fixture=data_png,
        expected=test_event,
    )


def test_scan_png_eof_pe_overlay(
    scan_png_eof: Scanner,
    data_pe_overlay_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "683f58a9-288f-5842-ba85-94060126684e",
                name=":png-trailer",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                size=4096,
                mime_type={"application/vnd.microsoft.portable-executable"},
            ),
        ],
        scan={
            "trailer_start": 539355,
        },
    )
    run_test_scan(
        scanner=scan_png_eof,
        fixture=data_pe_overlay_png,
        expected=test_event,
    )


def test_scan_png_eof_no_iend(
    scan_png_eof: Scanner,
    data_broken_iend_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"png_eof:no_iend_chunk"},
    )
    run_test_scan(
        scanner=scan_png_eof,
        fixture=data_broken_iend_png,
        expected=test_event,
    )
