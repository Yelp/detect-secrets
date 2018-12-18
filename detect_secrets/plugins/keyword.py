from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class KeywordDetector(RegexBasedDetector):
    """This checks if blacklisted keywords are present in the analyzed string."""

    secret_type = 'Password'
    blacklist = [
        re.compile(s, flags=re.IGNORECASE)
        for s in (
            r'pass =',
            r'password',
            r'passwd',
            r'pwd',
            r'secret',
            r'secrete',
            r'token',
        )
    ]
