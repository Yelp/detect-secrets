"""
This plugin searches for Slack tokens
"""
from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class SlackDetector(RegexBasedDetector):

    secret_type = 'Slack Token'

    blacklist = (
        re.compile(r'xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+', flags=re.IGNORECASE),
    )
