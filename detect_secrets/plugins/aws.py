"""
This plugin searches for AWS key IDs
"""
from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class AWSKeyDetector(RegexBasedDetector):

    secret_type = 'AWS Access Key'

    blacklist = (
        re.compile(r'AKIA[0-9A-Z]{16}'),
    )
