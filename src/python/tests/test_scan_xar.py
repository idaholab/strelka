from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    parse_timestamp,
    run_test_scan,
    make_child,
)


scan_xar = fixtures.scanners.xar
data_xar = fixtures.data("test.xar")


def test_scan_xar(
    scan_xar: Scanner,
    data_xar: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            # make_child(
            #    "4dab09c6-57b5-5c88-bfd1-1c6e911f4583",
            #    name=":bzip2-contents",
            #    sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
            #    size=4015,
            #    mime_type={"text/plain"},
            # ),
            make_child(
                "0611978c-ce35-5ce7-9fe9-c6153e86e8ea",
                path="lorem.txt",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                mime_type={"text/plain"},
                size=4015,
                owner="karl",
                group="karl",
                uid=1000,
                gid=1000,
                mode="0775",
                mtime=parse_timestamp("2022-12-26T20:46:47Z"),
            ),
        ],
        scan={
            "total": {
                "directories": 0,
                "extracted": 1,
                "files": 1,
                "other": 0,
            },
        },
    )
    run_test_scan(
        scanner=scan_xar,
        fixture=data_xar,
        expected=test_event,
    )
