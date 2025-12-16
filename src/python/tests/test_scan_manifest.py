from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_manifest = fixtures.scanners.manifest
data_json_manifest = fixtures.data("test_manifest.json")


def test_scan_manifest(
    scan_manifest: Scanner,
    data_json_manifest: File,
) -> None:
    """
    Pass:   Sample event matches output of the scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "name": "Focus Mode",
            "manifest_version": 3,
            "version": "1.0",
            "description": (
                "Enable reading mode on Chrome's official Extensions and Chrome Web "
                "Store documentation."
            ),
            "permissions": ["scripting", "activeTab"],
        },
    )
    run_test_scan(
        scanner=scan_manifest,
        fixture=data_json_manifest,
        expected=test_event,
    )
