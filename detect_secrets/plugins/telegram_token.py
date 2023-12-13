"""
This plugin searches for Telegram tokens
"""
import re
from detect_secrets.plugins.base import RegexBasedDetector


class TelegramTokenDetector(RegexBasedDetector):
    """Scans for Telegram tokens."""
    secret_type = 'Telegram Token'

    denylist = [
        re.compile(r'^\d{8,10}:[a-zA-Z\d_\-]{35}$'),
    ]
