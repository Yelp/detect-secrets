import re

from .base import RegexBasedDetector


class IPPublicDetector(RegexBasedDetector):
    """Scans for public ip address (ipv4)

    Some non-public ipv4 addresses are ignored, such as:
        - 127.
        - 10.
        - 172.(16-31)
        - 192.168.

    Reference:
    https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
    https://en.wikipedia.org/wiki/Private_network
    """
    secret_type = 'Public IP (ipv4)'

    denylist_ipv4_address = r"""
        (?<!\.)         # Negative lookbehind: Ensures no preceding dot
        \b              # Word boundary: Start of a word
        (?!             # Negative lookahead: Ensures the following pattern doesn't match
            192\.168\.  # Exclude "192.168."
            |127\.      # Exclude "127."
            |10\.       # Exclude "10."
            |172\.(?:1[6-9]|2[0-9]|3[01]) # Exclude "172." with specific ranges
        )
        (?:             # Non-capturing group for octets
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\. # Match numbers 0-255 followed by dot
        ){3}            # Repeat for three octets
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) # Match final octet (0-255)
        (?::\d{1,5})?   # Optional non-capturing group for port number (0-99999)
        \b              # Word boundary: End of a word
        (?!\.)          # Negative lookahead: Ensures no following dot
    """

    denylist = [
        re.compile(denylist_ipv4_address, flags=re.IGNORECASE | re.VERBOSE),
    ]
