"""
This plugin searches for Aiven tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class AivenTokenDetector(RegexBasedDetector):
    """Scans for Aiven tokens."""
    secret_type = 'Aiven Token'

    denylist = [
        # Aiven tokens follow the pattern: AVNS_<alphanumeric and underscores with a minimum length of 8>
        re.compile(r'AVNS_[\w]{8,}'),
    ]
