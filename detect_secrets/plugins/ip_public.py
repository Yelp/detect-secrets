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
        # Negative lookbehind: Checks if preceding character is not a digit
        (?<![0-9])
        # Negative lookahead: Checks if following pattern doesn't match
        (?!
            # Matches "192.168.", "127.", "10.", or "172." with specific ranges
            192\.168\.|
            127\.|
            10\.|
            172\.(?:1[6-9]|2[0-9]|3[01])
        )
        # Non-capturing group for numbers 0-255 followed by a dot
        (?:
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
        ){3}
        # Matches final number in an IP address (0-255)
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
        # Optional group for port number (0-99999)
        (?::\d{1,5})?
        # Negative lookahead: Ensures next character isn't a digit
        (?!
            [0-9]
        )
    """

    denylist = [
        re.compile(denylist_ipv4_address, flags=re.IGNORECASE | re.VERBOSE),
    ]
