from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_lnk = fixtures.scanners.lnk
data_lnk = fixtures.data("test.lnk")


def test_scan_lnk(
    scan_lnk: Scanner,
    data_lnk: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "drive_type": "DRIVE_FIXED",
            "drive_serial_number": "c2922660",
            "volume_label": "Local Disk",
            "local_base_path": r"C:\Windows\System32\calc.exe",
            "name_string": "Test Comment",
            "relative_path": r"..\..\..\..\Windows\System32\calc.exe",
            "working_dir": r"C:\Windows\System32",
            "command_line_args": "-testCommands",
            "machine_id": b"laptop-c77ajnj7",
            "mac": "38fc989e18fc",
        },
    )
    run_test_scan(
        scanner=scan_lnk,
        fixture=data_lnk,
        expected=test_event,
    )
