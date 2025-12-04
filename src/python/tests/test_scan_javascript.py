from strelka.testing import File, Scanner, fixtures, run_test_scan, make_event, make_indicator


scan_javascript = fixtures.scanners.javascript
data_js = fixtures.data("test.js")


def test_scan_javascript(
    scan_javascript: Scanner,
    data_js: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator(
                "domain-name",
                "another-example-bad-site.net",
            ),
            make_indicator(
                "domain-name",
                "example-malicious-site.com",
            ),
            make_indicator(
                "domain-name",
                "suspicious-ftp-server.org",
            ),
            make_indicator(
                "url",
                "ftp://suspicious-ftp-server.org",
            ),
            make_indicator(
                "url",
                "http://example-malicious-site.com",
            ),
            make_indicator(
                "url",
                "http://example-malicious-site.com/data",
            ),
            make_indicator(
                "url",
                "https://another-example-bad-site.net",
            ),
        ],
        scan={
            "tokens": [
                "BlockComment",
                "Identifier",
                "Keyword",
                "LineComment",
                "Numeric",
                "Punctuator",
                "RegularExpression",
                "String",
            ],
            "keywords": [
                "else",
                "for",
                "function",
                "if",
                "in",
                "new",
                "return",
                "this",
                "throw",
                "typeof",
                "var",
            ],
            "strings": [
                "",
                '" (',
                '".',
                ") in Handlebars partial Array => ",
                "-",
                "Checking URL: ",
                "Connection established",
                'Could not find partial with name "',
                "Fetching data from: ",
                'Found unknown type of partial "',
                "base64",
                "fs",
                "ftp://suspicious-ftp-server.org",
                "function",
                "http://example-malicious-site.com",
                "http://example-malicious-site.com/data",
                "https://another-example-bad-site.net",
                "open",
                "package.json",
                "path",
                "string",
                "use strict",
                "utf8",
                "ws",
            ],
            "identifiers": [
                "Buffer",
                "Handlebars",
                "JSON",
                "SafeString",
                "Utils",
                "WebSocket",
                "a",
                "arguments",
                "arr",
                "atob",
                "b",
                "btoa",
                "checkMultipleUrls",
                "code",
                "compile",
                "concat",
                "console",
                "context",
                "cwd",
                "dynamicEval",
                "escape",
                "escapeExpression",
                "establishWebSocket",
                "eval",
                "exports",
                "fetchDataFromUrl",
                "forEach",
                "fs",
                "hasOwnProperty",
                "helper",
                "helpers",
                "i",
                "join",
                "jsonStringify",
                "key",
                "length",
                "log",
                "module",
                "name",
                "obj",
                "on",
                "open",
                "opt",
                "params",
                "parse",
                "partial",
                "partials",
                "path",
                "pkg",
                "process",
                "readFileSync",
                "register",
                "registerHelper",
                "replace",
                "require",
                "send",
                "slugify",
                "str",
                "stringify",
                "suspiciousUrl",
                "toLowerCase",
                "toString",
                "url",
                "urls",
                "ws",
            ],
            "regular_expressions": [
                r"/ +/g",
                r"/[^\w ]+/g",
            ],
            "suspicious_keywords": [
                "WebSocket",
                "eval",
            ],
            "urls": [
                "ftp://suspicious-ftp-server.org",
                "http://example-malicious-site.com",
                "http://example-malicious-site.com/data",
                "https://another-example-bad-site.net",
            ],
            "beautified": True,
            "script_length_bytes": 3127,
        },
    )
    run_test_scan(
        scanner=scan_javascript,
        fixture=data_js,
        expected=test_event,
    )


def test_scan_javascript_max_strings(
    scan_javascript: Scanner,
    data_js: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator(
                "domain-name",
                "example-malicious-site.com",
            ),
            make_indicator(
                "domain-name",
                "suspicious-ftp-server.org",
            ),
            make_indicator(
                "url",
                "ftp://suspicious-ftp-server.org",
            ),
            make_indicator(
                "url",
                "http://example-malicious-site.com",
            ),
        ],
        scan={
            "tokens": [
                "BlockComment",
                "Identifier",
            ],
            "keywords": [
                "else",
                "for",
            ],
            "strings": [
                "",
                '" (',
            ],
            "identifiers": [
                "Buffer",
                "Handlebars",
            ],
            "regular_expressions": [
                "/ +/g",
                r"/[^\w ]+/g",
            ],
            "suspicious_keywords": [
                "WebSocket",
                "eval",
            ],
            "urls": [
                "ftp://suspicious-ftp-server.org",
                "http://example-malicious-site.com",
            ],
            "beautified": True,
            "script_length_bytes": 3127,
        },
    )
    run_test_scan(
        scanner=scan_javascript,
        fixture=data_js,
        options={
            "max_strings": 2,
        },
        expected=test_event,
    )
