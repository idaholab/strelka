from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_child,
    make_event,
    parse_timestamp,
    run_test_scan,
)


scan_email = fixtures.scanners.email
data_eml = fixtures.data("test.eml")
data_broken_eml = fixtures.data("test_broken.eml")


def test_scan_email(
    scan_email: Scanner,
    data_eml: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "cb9008cf-ad72-52c5-a05f-33c926a441f7",
                name="image001.jpg",
                sha1="af61b273c2d21cd4fe4479f2efe941aa809acdc9",
                mime_type={"image/jpeg"},
                size=21619,
            ),
            make_child(
                "3a856ebb-8649-5386-abd9-ec3af29ea496",
                name="test.doc",
                sha1="619e1e50cd735491adad7edcdfbe63e93537554d",
                mime_type={"application/msword"},
                size=51200,
            ),
        ],
        scan={
            "total": {
                "attachments": 2,
                "attachment_bytes": 72819,
                "extracted": 2,
            },
            "body": (
                "Lorem Ipsum\n"
                "\n"
                "[cid:image001.jpg@01D914BA.2B9507C0]\n"
                "\n"
                "\n"
                "Lorem ipsum dolor sit amet, consectetur adipisci...tristique mi, "
                "quis finibus justo augue non ligula. Quisque facilisis dui in orci "
                "aliquet fermentum.\n"
            ),
            "domains": [
                "1.0in",
                "div.msonormal",
                "div.wordsection1",
                "schemas.microsoft.com",
                "span.emailstyle17",
                "span.msohyperlink",
                "span.msohyperlinkfollowed",
                "www.w3.org",
            ],
            "subject": "Lorem Ipsum",
            "to": ["baz.quk@example.com"],
            "cc": [],
            "from": "foo.bar@example.com",
            "date_utc": parse_timestamp("2022-12-21T02:29:49.000Z"),
            "message_id": "DS7PR03MB5640AD212589DFB7CE58D90CFBEB9@DS7PR03MB5640.namprd03.prod.outlook.com",
            "received_domain": [
                "ch2pr03mb5366.namprd03.prod.outlook.com",
                "ds7pr03mb5640.namprd03.prod.outlook.com",
                "mx.example.com",
                "mx0a-0020ab02.pphosted.com",
                "mx0b-0020ab02.pphosted.com",
                "pps.filterd",
            ],
            "received_ip": [
                "022.12.20.18",
                "127.0.0.1",
                "2002:a05:6500:11d0:b0:17b:2a20:6c32",
                "205.220.177.243",
                "2603:10b6:5:2c0::11",
                "2603:10b6:610:96::16",
                "8.17.1.19",
                "fe80::bd8e:df17:2c2f:2490",
            ],
        },
    )
    run_test_scan(
        scanner=scan_email,
        fixture=data_eml,
        options={
            "create_thumbnail": False,
        },
        expected=test_event,
    )


def test_scan_email_incomplete(
    scan_email: Scanner,
    data_broken_eml: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "total": {
                "attachments": 0,
                "attachment_bytes": 0,
                "extracted": 0,
            },
            "body": (
                "Hi Placeholder,\n"
                "\n"
                "Can I have access?\n"
                "\n"
                "Thanks,\n"
                "John\n"
                "\n"
                "\n"
                "From: Placeholder Smith  <placeholder@acme.com<m...m> shared a file "
                "or folder located in Acme Share with you. Delete visitor "
                "session<https://acme.com>\n"
            ),
            "domains": ["acme.com", "share.acme.com"],
            "subject": "",
            "to": [],
            "cc": [],
            "from": "",
            "date_utc": parse_timestamp("1970-01-01T00:00:00.000Z"),
            "message_id": "",
            "received_domain": [],
            "received_ip": [],
        },
    )
    run_test_scan(
        scanner=scan_email,
        fixture=data_broken_eml,
        options={
            "create_thumbnail": True,
        },
        expected=test_event,
    )
