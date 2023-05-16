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
        (?<![0-9])                    # Negative lookbehind: Asserts that what immediately precedes the current position in the string is not a digit
        (?!                            # Negative lookahead: Asserts that what immediately follows the current position in the string does not match the enclosed pattern
            192\.168\.|                # Match "192.168."
            127\.|                     # Match "127."
            10\.|                      # Match "10."
            172\.(?:1[6-9]|2[0-9]|3[01])  # Match "172." followed by a number between 16 and 31
        )
        (?:                            # Non-capturing group: Groups the enclosed pattern but does not create a backreference
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # Match a number between 0 and 255 followed by a dot
        ){3}                           # Repeat the preceding non-capturing group three times
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)         # Match a number between 0 and 255
        (?::\d{1,5})?                   # Optional non-capturing group: Match a colon followed by a number between 0 and 99999 (a port number)
        (?!                            # Negative lookahead: Asserts that what immediately follows the current position in the string does not match the enclosed pattern
            [0-9]                       # Match a digit
        )
    """

    denylist = [
        re.compile(denylist_ipv4_address, flags=re.IGNORECASE | re.VERBOSE)
    ]
