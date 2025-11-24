from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_onenote = fixtures.scanners.onenote
data_one = fixtures.data("test.one")
data_onepkg = fixtures.data("test.onepkg")


def test_scan_onenote(
    scan_onenote: Scanner,
    data_one: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "441128ce-1afb-53b3-8cdc-f6cc91c86cb7",
                sha1="81866184343fff702cfdc37d1f28efa7e847cb81",
                mime_type=[
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                ],
                name=":file_8944",
                size=36980,
            ),
            make_child(
                "a2b27ef2-09b0-5f28-9223-38b34923b6aa",
                sha1="22a0478a8b95fadfeb63c29e1389c2273a451157",
                mime_type=["image/png"],
                name=":file_47800",
                size=1433,
            ),
        ],
        scan={
            "total": {
                "extracted": 2,
                "files": 2,
            },
        },
    )
    run_test_scan(
        scanner=scan_onenote,
        fixture=data_one,
        expected=test_event,
    )


def test_scan_onenotepkg(
    scan_onenote: Scanner,
    data_onepkg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "total": {
                "extracted": 0,
                "files": 0,
            },
        },
    )
    run_test_scan(
        scanner=scan_onenote,
        fixture=data_onepkg,
        expected=test_event,
    )
