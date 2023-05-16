import re
from .base import RegexBasedDetector

class EmailAddressDetector(RegexBasedDetector):
    """Email Address Detector.

    This class is designed to efficiently and accurately detect email addresses within given text. It primarily
    validates the general format of email addresses, and does not adhere strictly to email format standards such as RFC 5322.

    Key Features:
    - Ignores common, non-security-threatening email addresses to enhance precision.

    Limitations:
    - Despite robust detection mechanisms, the class is not infallible and may not cover all edge cases.
    - It does not support some examples from RFC 6530, e.g., email addresses with Greek alphabets.

    References: 
    - https://en.wikipedia.org/wiki/Email_address
    - https://stackoverflow.com/a/14321045
    """
    secret_type = 'Email Address'

    whitelist = ['noreply@github.com', 'git@github.com']
    # Excluses whitelist email addresses from detection to reduce false positives.

    base_pattern = r"""
        [\w+-]+                    # Local part before the @ symbol
        (?:\.[\w+-]+)*             # Optional dot-separated words in the local part
        @                          # The @ symbol
        [\w+-]+                    # Domain part after the @ symbol
        (?:\.[\w+-]+)*             # Optional dot-separated words in the domain part
        (?:\.[a-zA-Z]{2,4})        # TLD part
    """
    # Pattern Breakdown:
    # 1. [\w+-]+: Matches one or more of a-z, A-Z, _, +, - 
    #    Represents the local part of the email address before the @ symbol.
    # 2. (?:\.[\w+-]+)*: Matches zero or more of a-z, A-Z, _, +, -, but must start with a . (dot)
    #    Allows for dot-separated words in the local part of the email address.
    # 3. @: Matches the @ symbol.
    # 4. [\w+-]+: Matches one or more of a-z, A-Z, _, +, - 
    #    Represents the domain part of the email address after the @ symbol.
    # 5. (?:\.[\w+-]+)*: Matches zero or more of a-z, A-Z, _, +, -, but must start with a . (dot)
    #    Allows for dot-separated words in the domain part of the email address.
    # 6. (?:\.[a-zA-Z]{2,4}): Matches 2 to 4 instances of a-z, A-Z, starting with a . (dot)
    #    Represents the TLD (top-level domain) part of the email address.

    deny_pattern = r"(?!" + "|".join(re.escape(email) for email in whitelist) + r"$)" + base_pattern
    # Combines the base pattern with a negative lookahead to exclude whitelist email addresses.

    denylist = [
        re.compile(r"\b" + deny_pattern + r"\b", flags=re.VERBOSE)
    ]
