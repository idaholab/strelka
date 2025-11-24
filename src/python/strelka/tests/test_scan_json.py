from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_json = fixtures.scanners.json
data_json = fixtures.data("test.json")


def test_scan_json(
    scan_json: Scanner,
    data_json: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "keys": [
                "stuck",
                "hurry",
                "whale",
                "fierce",
                "several",
                "will",
                "behavior",
                "new",
                "coach",
                "step",
                "west",
                "powerful",
            ],
        },
    )
    run_test_scan(
        scanner=scan_json,
        fixture=data_json,
        expected=test_event,
    )
