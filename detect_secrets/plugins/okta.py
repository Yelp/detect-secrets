"""
This plugin searches for Okta API tokens
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class OktaDetector(RegexBasedDetector):
    """Scans for Okta API tokens."""
    secret_type = 'Okta API Token'

    denylist = [
        # refs: https://developer.okta.com/docs/guides/create-an-api-token/main/
        # ex from docs: 00QCjAl4MlV-WPXM...0HmjFx-vbGua
        re.compile(r'00[a-zA-Z0-9\-\_]{40,}'),
    ]
