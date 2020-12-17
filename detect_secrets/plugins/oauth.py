import re

from detect_secrets.plugins.base import RegexBasedDetector


class BasicOauthDetector(RegexBasedDetector):
    """Scans for Square OAuth Secrets"""
    secret_type = 'Square OAuth Secrets'

    denylist = [
        re.compile(r'sq0csp-[0-9A-Za-z\\-_]{43}')
    ]