from __future__ import absolute_import

import re

from .base import RegexBasedDetector


SPECIAL_URL_CHARACTERS = ':/?#[]@'


class BasicAuthDetector(RegexBasedDetector):

    secret_type = 'Basic Auth Credentials'
    blacklist = [
        re.compile(
            r'://[^{}\s]+:([^{}\s]+)@'.format(
                re.escape(SPECIAL_URL_CHARACTERS),
                re.escape(SPECIAL_URL_CHARACTERS),
            ),
        ),
    ]
