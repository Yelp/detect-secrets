from __future__ import absolute_import

import re

from .base import RegexBasedDetector


RESERVED_CHARACTERS = ':/?#[]@'
SUB_DELIMITER_CHARACTERS = '!$&\';'  # and anything else we might need


class BasicAuthDetector(RegexBasedDetector):

    secret_type = 'Basic Auth Credentials'

    blacklist = [
        re.compile(
            r'://[^{}\s]+:([^{}\s]+)@'.format(
                re.escape(RESERVED_CHARACTERS + SUB_DELIMITER_CHARACTERS),
                re.escape(RESERVED_CHARACTERS + SUB_DELIMITER_CHARACTERS),
            ),
        ),
    ]
