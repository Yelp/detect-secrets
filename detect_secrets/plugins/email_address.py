import re

from .base import RegexBasedDetector


class EmailAddressDetector(RegexBasedDetector):
    """
    A detector for identifying email addresses within text. It uses regular expressions to
    focus on general email structures, not strictly adhering to standards like RFC 5322.
    Designed for efficient and broad detection, it also has some limitations.

    Features:
    - Detects a wide range of email formats efficiently.
    - Ignores common, non-critical emails to minimize false positives.

    Limitations:
    - May miss edge cases or unconventional email formats.
    - Not compliant with advanced formats, e.g., RFC 6530 non-Latin emails.

    Regular Expression:
    Utilizes a regex pattern focusing on typical email components: local part, domain, TLD.
    Excludes predefined whitelist emails to reduce false positives.

    References:
    - https://en.wikipedia.org/wiki/Email_address
    - https://stackoverflow.com/a/14321045
    """
    secret_type = 'Email Address'

    # Excluses whitelist email addresses from detection to reduce false positives.
    whitelist = ['noreply@github.com', 'git@github.com']

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

    deny_pattern = r'(?!' \
                   + '|'.join(re.escape(email) for email in whitelist) \
                   + r'$)' + base_pattern
    # Combines the base pattern with a negative lookahead to exclude whitelist email addresses.

    denylist = [
        re.compile(r'\b' + deny_pattern + r'\b', flags=re.VERBOSE),
    ]
