# fmt: off

import logging
import subprocess

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


def retrieve_signatures():
    """
    Utility function that will retrieve the ClamAV signature DB when called. Currently this is set up to run
    when initializing the ClamAV scanner test. Should take around 10-15 seconds to retrieve the signatures from the remote DB.
    """
    logging.info("Retrieving ClamAV signatures via freshclam.")
    try:
        # Run freshclam to get the newest database signature
        with subprocess.Popen(
            ["freshclam"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            stdout, stderr = proc.communicate()

        logging.info(stdout)

    except Exception as e:
        error_msg = f"Failed to download clam signatures: {e}"
        logging.error(error_msg)


def test_scan_clamav(
    scan_clamav: Scanner,
    data_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    retrieve_signatures()
    test_event = make_event(
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


def test_scan_clamav_eicar(
    scan_clamav: Scanner,
    data_eicar_com: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
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
