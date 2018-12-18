from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class PrivateKeyDetector(RegexBasedDetector):
    """This checks for private keys by determining whether the blacklisted
    lines are present in the analyzed string.
    """

    secret_type = 'Private Key'
    blacklist = [
        re.compile(regexp)
        for regexp in (
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN DSA PRIVATE KEY',
            r'BEGIN EC PRIVATE KEY',
            r'BEGIN OPENSSH PRIVATE KEY',
            r'BEGIN PRIVATE KEY',
            r'PuTTY-User-Key-File-2',
            r'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
        )
    ]
