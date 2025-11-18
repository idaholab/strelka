from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_event,
    run_test_scan,
    make_child,
)


scan_bzip2 = fixtures.scanners.bzip2
data_bz2 = fixtures.data("test.bz2")


def test_scan_bzip2(
    scan_bzip2: Scanner,
    data_bz2: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "4dab09c6-57b5-5c88-bfd1-1c6e911f4583",
                name=":bzip2-contents",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                size=4015,
                mime_type={"text/plain"},
            ),
        ],
    )
    run_test_scan(
        scanner=scan_bzip2,
        fixture=data_bz2,
        expected=test_event,
    )
