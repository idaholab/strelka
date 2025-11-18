from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_event,
    parse_timestamp,
    run_test_scan,
    make_child,
)


scan_iso = fixtures.scanners.iso
data_iso = fixtures.data("test.iso")


def test_scan_iso(
    scan_iso: Scanner,
    data_iso: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "a3106a95-aa13-5d6f-a84c-d8058426daad",
                path="/",
                mtime=parse_timestamp("2022-12-12T00:42:00Z"),
                type="directory",
            ),
            make_child(
                "4cb4e68f-6320-557b-ac15-772d32338cf2",
                path="/lorem.txt",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                size=4015,
                mime_type=["text/plain"],
                mtime=parse_timestamp("2022-12-12T00:44:49Z"),
            ),
        ],
        scan={
            "total": {
                "directories": 1,
                "files": 1,
                "extracted": 1,
            },
            "meta": {
                "date_created": parse_timestamp("2022-12-12T00:42:00.85Z"),
                "date_effective": None,
                "date_expiration": None,
                "date_modification": parse_timestamp("2022-12-12T00:42:00.85Z"),
                "format": "joliet",
                "volume_identifier": "NEW_VOLUME",
                "raw_volume_identifier": "NEW_VOLUME                      ",
            },
        },
    )
    run_test_scan(
        scanner=scan_iso,
        fixture=data_iso,
        expected=test_event,
    )
