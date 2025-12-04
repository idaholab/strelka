from strelka.testing import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_gif_eof = fixtures.scanners.gif_eof
data_gif = fixtures.data("test.gif")
data_pe_overlay_gif = fixtures.data("test_pe_overlay.gif")


def test_scan_gif_eof_no_trailer(
    scan_gif_eof: Scanner,
    data_gif: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"gif_eof:no_trailer"},
    )
    run_test_scan(
        scanner=scan_gif_eof,
        fixture=data_gif,
        expected=test_event,
    )


def test_scan_gif_eof(
    scan_gif_eof: Scanner,
    data_pe_overlay_gif: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "c33915c9-b982-5ea8-a900-4f5138c0f49b",
                name=":gif-trailer",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                size=4096,
                mime_type={"application/vnd.microsoft.portable-executable"},
            ),
        ],
        scan={
            "trailer_start": 1062297,
        },
    )
    run_test_scan(
        scanner=scan_gif_eof,
        fixture=data_pe_overlay_gif,
        expected=test_event,
    )
