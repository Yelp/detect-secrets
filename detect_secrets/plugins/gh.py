from __future__ import absolute_import

import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class GHDetector(RegexBasedDetector):

    secret_type = 'GitHub Credentials'

    denylist = [
        # GitHub tokens (PAT & OAuth) are 40 hex characters
        re.compile(r'(?:(?<=\W)|(?<=^))([0-9a-f]{40})(?:(?=\W)|(?=$))'),  # 40 hex
    ]

    def verify(self, token):
        try:
            if type(token) == bytes:
                token = token.decode('UTF-8')
            headers = {'Authorization': 'token %s' % token}
            response = requests.get('https://github.ibm.com/api/v3', headers=headers)
            if response.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif response.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            else:
                return VerifiedResult.UNVERIFIED
        except Exception:
            return VerifiedResult.UNVERIFIED
