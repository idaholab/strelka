from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_encrypted_doc = fixtures.scanners.encrypted_doc
data_password_doc = fixtures.data("test_password.doc")
data_password_docx = fixtures.data("test_password.docx")
data_password_brute_doc = fixtures.data("test_password_brute.doc")
data_password_brute_docx = fixtures.data("test_password_brute.docx")
helper_passwords = fixtures.helpers("test_passwords.dat")


def test_scan_encrypted_doc(
    scan_encrypted_doc: Scanner,
    data_password_doc: File,
    helper_passwords: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_passwords.path is not None
    test_event = make_event(
        scan={
            "flags": ["cracked_by_wordlist"],
            "cracked_password": b"Password1!",
        },
    )
    run_test_scan(
        scanner=scan_encrypted_doc,
        fixture=data_password_doc,
        options={
            "log_pws": True,
            "password_file": helper_passwords.path,
        },
        expected=test_event,
    )


def test_scan_encrypted_docx(
    scan_encrypted_doc: Scanner,
    data_password_docx: File,
    helper_passwords: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_passwords.path is not None
    test_event = make_event(
        scan={
            "flags": ["cracked_by_wordlist"],
            "cracked_password": b"Password1!",
        },
    )
    run_test_scan(
        scanner=scan_encrypted_doc,
        fixture=data_password_docx,
        options={
            "log_pws": True,
            "password_file": helper_passwords.path,
        },
        expected=test_event,
    )


def test_scan_encrypted_doc_brute(
    scan_encrypted_doc: Scanner,
    data_password_brute_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "flags": ["cracked_by_incremental"],
            "cracked_password": b"aaa",
        },
    )
    run_test_scan(
        scanner=scan_encrypted_doc,
        fixture=data_password_brute_doc,
        options={
            "scanner_timeout": 120,
            "log_pws": True,
            "brute_force": True,
            "min_length": 1,
            "max_length": 3,
        },
        expected=test_event,
    )


def test_scan_encrypted_docx_brute(
    scan_encrypted_doc: Scanner,
    data_password_brute_docx: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "flags": ["cracked_by_incremental"],
            "cracked_password": b"aaa",
        },
    )
    run_test_scan(
        scanner=scan_encrypted_doc,
        fixture=data_password_brute_docx,
        options={
            "scanner_timeout": 120,
            "log_pws": True,
            "brute_force": True,
            "min_length": 1,
            "max_length": 3,
        },
        expected=test_event,
    )
