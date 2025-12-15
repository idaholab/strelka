from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_ini = fixtures.scanners.ini
data_ini = fixtures.data("test.ini")


def test_scan_ini(
    scan_ini: Scanner,
    data_ini: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "comments": [
                b"; Lorem ipsum dolor sit amet, consectetur adipiscing elit,",
                b";sed do eiusmod tempor incididunt ut labore et dolore magna",
                b";aliqua.",
                b"# Elementum sagittis vitae et leo duis ut diam.",
                b"# Nulla facilisi etiam dignissim diam quis.",
            ],
            "keys": [
                {"section": b"Lorem", "name": b"Update", "value": b"300"},
                {"section": b"Lorem", "name": b"Repeat", "value": b"24"},
                {"section": b"Ipsum", "name": b"Name", "value": b"Lorem Ipsum"},
                {"section": b"Ipsum", "name": b"Author", "value": b"Lorem"},
                {
                    "section": b"Ipsum",
                    "name": b"Information",
                    "value": b"Volutpat commodo sed egestas egestas.",
                },
                {"section": b"Ipsum", "name": b"License", "value": b"Ipsum"},
                {"section": b"Ipsum", "name": b"Version", "value": b"1.0.1"},
            ],
            "sections": [
                b"Lorem",
                b"Ipsum",
            ],
        },
    )
    run_test_scan(
        scanner=scan_ini,
        fixture=data_ini,
        expected=test_event,
    )
