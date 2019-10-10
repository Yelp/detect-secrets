from __future__ import absolute_import

import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class SoftLayerDetector(RegexBasedDetector):

    secret_type = 'SoftLayer Credentials'

    # opt means optional
    sl = r'(?:softlayer|sl)(?:_|-|)(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-z0-9]{64})'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=sl,
            password_keyword_regex=key_or_pass,
            password_regex=secret,
        ),

        re.compile(
            r'(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})',
            flags=re.IGNORECASE,
        ),
    ]

    def verify(self, token, content, potential_secret=None):
        usernames = find_username(content)
        if not usernames:
            return VerifiedResult.UNVERIFIED

        for username in usernames:
            return verify_softlayer_key(username, token, potential_secret)

        return VerifiedResult.VERIFIED_FALSE


def find_username(content):
    # opt means optional
    username_keyword = r'(?:username|id|user|userid|user-id|user-name|' + \
        r'name|user_id|user_name|uname)'
    username = r'(\w(?:\w|_|@|\.|-)+)'
    regex = re.compile(
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=SoftLayerDetector.sl,
            password_keyword_regex=username_keyword,
            password_regex=username,
        ),
    )

    return [
        match
        for line in content.splitlines()
        for match in regex.findall(line)
    ]


def verify_softlayer_key(username, token, potential_secret=None):
    try:
        headers = {'Content-type': 'application/json'}
        response = requests.get(
            'https://api.softlayer.com/rest/v3/SoftLayer_Account.json',
            auth=(username, token), headers=headers,
        )

        if response.status_code == 200:
            if potential_secret:
                potential_secret.other_factors['username'] = username
            return VerifiedResult.VERIFIED_TRUE
        else:
            return VerifiedResult.VERIFIED_FALSE
    except Exception:
        return VerifiedResult.UNVERIFIED
