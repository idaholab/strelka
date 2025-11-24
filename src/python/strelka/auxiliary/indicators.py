from typing import TypeVar, cast

from .urls import data_uri, domain, expand_idna_domain, ipv4, ipv6, netloc, uri, url


__all__ = (
    "data_uri",
    "domain",
    "expand_idna_domain",
    "extract_domains",
    "extract_ip_addresses",
    "extract_uris",
    "extract_urls",
    "ipv4",
    "ipv6",
    "netloc",
    "uri",
    "url",
)


# Regarding the IDNA valid unicode codepoints:
#     c.f. https://www.rfc-editor.org/rfc/rfc5892
# Regarding the registered URI schemes:
#     c.f. https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
# Regarding the IPv4/IPv6 address regexes:
#     c.f. https://stackoverflow.com/questions/53497

########################################################################################


_T = TypeVar("_T", str, bytes)


def extract_uris(text: _T) -> set[_T]:
    """
    Extracts URIs from a string.
    Args:
        text (str): The input string to search for URIs.
    Returns:
        set: A set of unique URIs extracted from the input string.
    """
    return cast(set[_T], {*uri.findall(text)})


def extract_urls(text: _T) -> set[_T]:
    """
    Extracts URLs from a string.
    Args:
        text (str): The input string to search for URLs.
    Returns:
        set: A set of unique URLs extracted from the input string.
    """
    return cast(set[_T], {*url.findall(text)})


def extract_domains(text: _T) -> set[_T]:
    """
    Extracts domain names from a string containing URLs.
    Args:
        text (str): The input string to search for URLs.
    Returns:
        set: A set of unique domain names extracted from the URLs.
    """
    domains = set()
    for match in uri.finditer(text):
        if host := match.group("host"):
            domains.update(expand_idna_domain(host))
    return domains


def extract_ip_addresses(text: _T) -> set[_T]:
    """
    Extracts IP addresses from a string.
    Args:
        text (str): The input string to search for IP addresses.
    Returns:
        set: A set of unique IP addresses extracted from the input string.
    """
    return cast(set[_T], {*ipv4.findall(text), *ipv6.findall(text)})


def extract_indicators_from_string(text: _T) -> set[_T]:
    """
    Extracts various types of indicators from a string.
    This function looks for domain names and IP addresses within the given string.
    Args:
        text (str): The input string to search for indicators.
    Returns:
        set: A set of unique extracted indicators.
    """
    return {
        *extract_domains(text),
        *extract_ip_addresses(text),
    }
