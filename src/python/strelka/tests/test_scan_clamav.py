import logging
from pathlib import Path
import subprocess

import clamd
from pytest import fixture

from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_event,
    make_indicator,
    make_rule,
    run_test_scan,
)


scan_clamav = fixtures.scanners.clamav
data_png = fixtures.data("test.png")
data_eicar_com = fixtures.data("test_eicar.com")


@fixture(scope="session")
def clamav_signatures() -> None:
    # do the signatures exist in the standard location?
    if Path("/var/lib/clamav/main.cvd").exists():
        return

    # hmmm... they're not in the standard location, let's try to run clamscan
    result = subprocess.run(
        ["clamscan", "--quiet", "-"],
        input="",
        capture_output=True,
    )
    if result.returncode != 2:
        return

    # nope, no signatures, run freshclam to acquire some
    logging.info("Retrieving ClamAV signatures via freshclam...")
    result = subprocess.run(
        ["freshclam"],
        capture_output=True,
        check=True,
    )
    logging.info(f"Output from freshclam:\n{result.stdout}")


@fixture(scope="session")
def clamd_socket() -> str:
    assert clamd.ClamdNetworkSocket(host="localhost").ping() == "PONG"
    return "localhost"


def test_scan_clamav_remote(
    scan_clamav: Scanner,
    data_png: File,
    clamd_socket: str,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"clamav:remote"},
    )
    run_test_scan(
        scanner=scan_clamav,
        fixture=data_png,
        expected=test_event,
        options={"clamd_socket": clamd_socket},
    )


def test_scan_clamav_remote_eicar(
    scan_clamav: Scanner,
    data_eicar_com: File,
    clamd_socket: str,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={
            "clamav:remote",
            "clamav:signature_match",
        },
        rules=[
            make_rule(
                provider="clamav",
                name="Eicar-Signature",
            ),
        ],
    )
    run_test_scan(
        scanner=scan_clamav,
        fixture=data_eicar_com,
        expected=test_event,
        options={"clamd_socket": clamd_socket},
    )


def test_scan_clamav_local(
    scan_clamav: Scanner,
    data_png: File,
    clamav_signatures,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"clamav:local"},
        related=[
            make_indicator("md5", "8d39d685063ed37f21bc13a91276c2ca"),
        ],
        scan={
            "magic": "CLAMJSONv0",
            "root_file_type": "CL_TYPE_PNG",
            "file_md5": "8d39d685063ed37f21bc13a91276c2ca",
            "file_name": "test.png",
            "file_size": 539355,
            "file_type": "CL_TYPE_PNG",
            "image_fuzzy_hash": {
                "hash": "83b45dde63a52313",
            },
        },
    )
    run_test_scan(
        scanner=scan_clamav,
        fixture=data_png,
        expected=test_event,
    )


def test_scan_clamav_local_eicar(
    scan_clamav: Scanner,
    data_eicar_com: File,
    clamav_signatures,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={
            "clamav:local",
            "clamav:signature_match",
        },
        related=[
            make_indicator("md5", "69630e4574ec6798239b091cda43dca0"),
        ],
        scan={
            "magic": "CLAMJSONv0",
            "root_file_type": "CL_TYPE_TEXT_ASCII",
            "file_md5": "69630e4574ec6798239b091cda43dca0",
            "file_name": "test_eicar.com",
            "file_size": 69,
            "file_type": "CL_TYPE_TEXT_ASCII",
            "viruses": ["Eicar-Signature"],
        },
        rules=[
            make_rule(
                provider="clamav",
                name="Eicar-Signature",
            ),
        ],
    )
    run_test_scan(
        scanner=scan_clamav,
        fixture=data_eicar_com,
        expected=test_event,
    )
