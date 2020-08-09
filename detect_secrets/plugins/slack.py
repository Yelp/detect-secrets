"""
This plugin searches for Slack tokens
"""
import re

import requests

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector


class SlackDetector(RegexBasedDetector):
    """Scans for Slack tokens."""
    secret_type = 'Slack Token'

    denylist = (
        # Slack Token
        re.compile(r'xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+', flags=re.IGNORECASE),
        # Slack Webhooks
        re.compile(
            r'https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    )

    def verify(self, token, **kwargs):  # pragma: no cover
        if token.startswith('https://hooks.slack.com/services/T'):
            response = requests.post(
                token,
                json={
                    'text': '',
                },
            )
            valid = response.text in ['missing_text_or_fallback_or_attachments', 'no_text']
        else:
            response = requests.post(
                'https://slack.com/api/auth.test',
                data={
                    'token': token,
                },
            ).json()
            valid = response['ok']

        return (
            VerifiedResult.VERIFIED_TRUE
            if valid
            else VerifiedResult.VERIFIED_FALSE
        )
