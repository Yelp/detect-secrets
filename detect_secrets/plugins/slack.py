"""
This plugin searches for Slack tokens
"""
from __future__ import absolute_import

import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class SlackDetector(RegexBasedDetector):

    secret_type = 'Slack Token'

    denylist = (
        re.compile(r'xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+', flags=re.IGNORECASE),
    )

    def verify(self, token, **kwargs):
        response = requests.post(
            'https://slack.com/api/auth.test',
            data={
                'token': token,
            },
        ).json()

        return VerifiedResult.VERIFIED_TRUE if response['ok'] \
            else VerifiedResult.VERIFIED_FALSE
