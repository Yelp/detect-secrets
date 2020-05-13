"""
This plugin searches for Twilio API keys
"""
import re

from .base import RegexBasedDetector


class TwilioKeyDetector(RegexBasedDetector):
    """Scans for Twilio API keys."""
    secret_type = 'Twilio API Key'

    denylist = [
        # Account SID (ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)  # pragma: whitelist secret
        re.compile(r'AC[a-z0-9]{32}'),

        # Auth token (SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)  # pragma: whitelist secret
        re.compile(r'SK[a-z0-9]{32}'),
    ]
