"""
This plugin searches for Twilio API keys
"""
from __future__ import absolute_import

import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class TwilioKeyDetector(RegexBasedDetector):
    """Scans for Twilio API keys."""
    secret_type = 'Twilio API Key'

    denylist = [
        # Account SID (ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
        re.compile(r'AC[a-z0-9]{32}'),

        # Auth token (SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
        re.compile(r'SK[a-z0-9]{32}'),
    ]
