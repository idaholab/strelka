from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_batch = fixtures.scanners.batch
data_bat = fixtures.data("test.bat")


def test_scan_batch(
    scan_batch: Scanner,
    data_bat: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "script_length_bytes": 515,
            "token_types": [
                "Token.Comment.Single",
                "Token.Keyword",
                "Token.Literal.String.Double",
                "Token.Name.Label",
                "Token.Name.Variable",
                "Token.Operator",
                "Token.Punctuation",
                "Token.Text",
            ],
            "tokens": {
                "comments": [
                    r"REM Simple batch script for calling avrdude "
                    r"with options for USBtinyISP",
                    r"REM (C) 2012, 2013 Michael Bemmerl",
                    r"REM License: WTFPL-2.0",
                ],
                "keywords": [
                    r"echo",
                    r"SETLOCAL",
                    r"SET",
                    r"IF",
                    r"NOT",
                    r"GOTO",
                ],
                "labels": [
                    r"help",
                    r"exit",
                ],
                "strings": [
                    r"avrdude",
                    r"\\bin\\avrdude.exe",
                ],
                "text": [
                    r"off",
                    r"\n",
                    r"\n\n",
                    r"-c",
                    r"usbtiny",
                    r"-P",
                    r"usb",
                    r"You",
                    r"probably",
                    r"want",
                    r"to",
                    r"add",
                    r"at",
                    r"least",
                    r"the",
                    r"part",
                    r"option",
                    r"-p",
                    r"[partno]",
                    r".",
                    r"and",
                    r"some",
                    r"other",
                    r"AVRDUDE",
                    r"command",
                    r"line",
                    r"like",
                    r"-U",
                    r"flash:w:[file]",
                ],
                "variables": [
                    r"AVRDUDE",
                    r"%AVR32_HOME%",
                    r"%1",
                    r"%AVRDUDE%",
                    r"%*",
                ],
            },
        },
    )
    run_test_scan(
        scanner=scan_batch,
        fixture=data_bat,
        expected=test_event,
    )
