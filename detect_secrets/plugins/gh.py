from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class GHDetector(RegexBasedDetector):

    secret_type = 'GitHub Credentials'

    denylist = [
        # GitHub tokens (PAT & OAuth) are 40 hex characters
        re.compile(r'(?:(?<=\W)|(?<=^))([0-9a-f]{40})(?:(?=\W)|(?=$))'),  # 40 hex
    ]
