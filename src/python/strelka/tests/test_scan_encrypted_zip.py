from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_encrypted_zip = fixtures.scanners.encrypted_zip
data_zip_password_zip = fixtures.data("test_zip_password.zip")
data_aes256_password_zip = fixtures.data("test_aes256_password.zip")


def test_scan_encrypted_zip(
    scan_encrypted_zip: Scanner,
    data_zip_password_zip: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[],
        scan={
            "flags": ["cracked_by_wordlist"],
            "total": {
                "files": 4,
                "extracted": 4,
            },
        },
    )
    run_test_scan(
        scanner=scan_encrypted_zip,
        fixture=data_zip_password_zip,
        expected=test_event,
    )


def test_scan_encrypted_zip_aes256(
    scan_encrypted_zip: Scanner,
    data_aes256_password_zip: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[],
        scan={
            "flags": ["cracked_by_wordlist"],
            "total": {
                "files": 4,
                "extracted": 4,
            },
        },
    )
    run_test_scan(
        scanner=scan_encrypted_zip,
        fixture=data_aes256_password_zip,
        expected=test_event,
    )
