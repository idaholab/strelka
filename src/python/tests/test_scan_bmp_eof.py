from strelka.testing import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_bmp_eof = fixtures.scanners.bmp_eof
data_bmp = fixtures.data("test.bmp")
data_pe_overlay_bmp = fixtures.data("test_pe_overlay.bmp")


def test_scan_bmp_eof_no_trailer(
    scan_bmp_eof: Scanner,
    data_bmp: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"bmp_eof:no_trailer"},
    )
    run_test_scan(
        scanner=scan_bmp_eof,
        fixture=data_bmp,
        expected=test_event,
    )


def test_scan_bmp_eof_pe_overlay(
    scan_bmp_eof: Scanner,
    data_pe_overlay_bmp: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "7b191dff-9c2d-549f-8623-8ae4d113f6ef",
                name=":bmp-trailer",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                size=4096,
                mime_type={"application/vnd.microsoft.portable-executable"},
            ),
        ],
        scan={
            "trailer_start": 249954,
        },
    )
    run_test_scan(
        scanner=scan_bmp_eof,
        fixture=data_pe_overlay_bmp,
        expected=test_event,
    )
