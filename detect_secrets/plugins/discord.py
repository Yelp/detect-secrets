"""
This plugin searches for Discord Bot Token
"""
import re

from .base import RegexBasedDetector


class DiscordBotTokenDetector(RegexBasedDetector):
    """Scans for Discord Bot token."""
    secret_type = 'Discord Bot Token'

    denylist = [
        # Discord Bot Token ([M|N]XXXXXXXXXXXXXXXXXXXXXXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXX)
        # Reference: https://discord.com/developers/docs/reference#authentication
        re.compile(r'[MN][a-zA-Z\d_-]{23}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}'),
    ]
