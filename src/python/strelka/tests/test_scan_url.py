from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_child,
    make_event,
    make_indicator,
    run_test_scan,
)


scan_url = fixtures.scanners.url
data_url = fixtures.data("test.url")
data_html = fixtures.data("test.html")


def test_scan_url_text(
    scan_url: Scanner,
    data_url: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator("domain-name", "barfoo.example.com"),
            make_indicator("domain-name", "foobar.example.com"),
            make_indicator("url", "ftp://barfoo.example.com"),
            make_indicator("url", "http://foobar.example.com"),
            make_indicator("url", "https://barfoo.example.com"),
        ],
        scan={
            "urls": {
                "http://foobar.example.com",
                "https://barfoo.example.com",
                "ftp://barfoo.example.com",
            },
        },
    )
    run_test_scan(
        scanner=scan_url,
        fixture=data_url,
        expected=test_event,
    )


def test_scan_url_text_uris(
    scan_url: Scanner,
    data_url: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator("domain-name", "barfoo.example.com"),
            make_indicator("domain-name", "foobar.example.com"),
            make_indicator("email-addr", "user@example.com"),
            make_indicator("url", "ftp://barfoo.example.com"),
            make_indicator("url", "http://foobar.example.com"),
            make_indicator("url", "https://barfoo.example.com"),
        ],
        scan={
            "urls": {
                "http://foobar.example.com",
                "https://barfoo.example.com",
                "ftp://barfoo.example.com",
                "mailto:user@example.com",
            },
        },
    )
    run_test_scan(
        scanner=scan_url,
        fixture=data_url,
        options={
            "include_uris": True,
        },
        expected=test_event,
    )


def test_scan_url_html(
    scan_url: Scanner,
    data_html: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator("domain-name", "example.com"),
            make_indicator("url", "https://example.com/example.js"),
        ],
        scan={
            "urls": {"https://example.com/example.js"},
        },
    )
    run_test_scan(
        scanner=scan_url,
        fixture=data_html,
        expected=test_event,
    )


def test_scan_url_html_uris(
    scan_url: Scanner,
    data_html: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "9d3a0082-acf4-5c66-9044-2fee28307a56",
                name=":data-uri@5608",
                sha1="5f9b4de66cc6a163081b97a4ef038dcd56c66ec1",
                mime_type=["image/png"],
                size=961,
            ),
        ],
        related=[
            make_indicator("domain-name", "example.com"),
            make_indicator("url", "https://example.com/example.js"),
        ],
        scan={
            "urls": {
                "https://example.com/example.js",
                (
                    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOAAAABYCAIAAABj1myu"
                    "AAADiElEQVR42u3ZX0rrQBiG8ap4WRDv3YBQ3ISLEKQUwQ24Ed1AQUopuAg3Ie5DvC"
                    "/VM/BxPj4yk9gc5yRv4fldiNYmnWSe5k979P39PQFUHREolBEopBEopBEopBEopBEo"
                    "pBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopB"
                    "EopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopBEopI0f6PHxsf2yXq9vb2/H"
                    "3iG/8vn5eX5+nj/+9vY2m83GHt1BItCaCLQ6Aq2JQKsj0Pp2u93p6an9/vHxcXZ2Nv"
                    "aIDthhBJqm/P7+frVa2Z+LxeLp6SlO/N3dnf03HasuLy9fXl7m87mvMC1uj/jz079u"
                    "bm5OTk4aY0g9pZ8PDw++NjvybTYbWzy99HK59AXbRtsWqL9QWvPFxYW/UL7a9/f3x8"
                    "fH4ibHldjwiq9Yd6PGcgCBpqm6urrKH0+79fn52X73QNODPqm2wrbTbrLdbm1WfAxx"
                    "cZOmM4Zivr6+OrZon0CLfLW+OcUn9A20ykaNRT3QuOttPvJHJi0zaiuMBxKbOT9y+C"
                    "t2d5PrPnHvE6gfwuOTbTw+vMnft5CfQP4t0CobNRb1QONpyI+X8Zhqc+aBNs7d/sy4"
                    "8nhMbUy5Py0WbzNXfGMU7XmK9zXEItN44tnAN9mGZH/2DbTKRo1FPdBYXrEwO8bEa9"
                    "C4l+PcF9ni+VE2fw9MWvLK9Q208VqNMadMr6+vi1fM+1+D/n6jxnKQgebz0RZo28Wc"
                    "Uwg0f78Vz85+QCXQQf3XI2hx8Y4xKBxBfRv9vtvZ2gh0UHWvQRt7uTglLr+qGyXQxj"
                    "amP+N+iO9GWyrentv442gJtLKOm820Z6fTaa+7+MZejk+On/b58alxk/TLufzxm6R8"
                    "DXGReLniI+k4XbTtNAKtqTvQtGd7fQ6a7+WOz0En2V38YIHmivfaxSfkOyR+0kmglf"
                    "0Y6KTnN0nFvZx/MRNvjYcPNNX2+vrq44krtO+94n/z7Y3Dsy/PuAZFBeI1CCLQQRFo"
                    "XwQ6KALti0AHRaB9ESikESikESikESikESikESikESikESikESikESikESikESikES"
                    "ikESikESikESikESikESikESikESikESikESikESikESikESikESikESikESikESik"
                    "ESikESikESikESikESik/QGie8qNG/5sjAAAAABJRU5ErkJggg=="
                ),
            },
        },
    )
    run_test_scan(
        scanner=scan_url,
        fixture=data_html,
        options={
            "include_uris": True,
            "extract_data_uris": True,
        },
        expected=test_event,
    )
