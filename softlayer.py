from __future__ import absolute_import

import re

import requests

from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class SoftLayerDetector(RegexBasedDetector):

    secret_type = 'SoftLayer Credentials'

    # opt means optional
    opt_quote = r'(?:"|\'|)'
    opt_dashes = r'(?:--|)'
    sl = r'(?:softlayer|sl)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    opt_space = r'(?: *)'
    opt_assignment = r'(?:=|:|:=|=>|)'
    secret = r'([a-z0-9]{64})'
    denylist = [
        re.compile(
            r'{opt_quote}{opt_dashes}{sl}{opt_dash_undrscr}{opt_api}{opt_dash_undrscr}{key_or_pass}'
            '{opt_quote}{opt_space}{opt_assignment}{opt_space}{opt_quote}{secret}'
            '{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_dashes=opt_dashes,
                sl=sl,
                opt_dash_undrscr=opt_dash_undrscr,
                opt_api=opt_api,
                key_or_pass=key_or_pass,
                opt_space=opt_space,
                opt_assignment=opt_assignment,
                secret=secret,
            ), flags=re.IGNORECASE,
        ),
        re.compile(
            r'(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})',
            flags=re.IGNORECASE,
        ),
    ]

    def verify(self, token, content, potential_secret=None):
        usernames = get_username(content)
        if not usernames:
            return VerifiedResult.UNVERIFIED

        for username in usernames:
            return verify_softlayer_key(username, token, potential_secret)

        return VerifiedResult.VERIFIED_FALSE


def get_username(content):
    # opt means optional
    opt_quote = r'(?:"|\'|)'
    opt_dashes = r'(?:--|)'
    opt_sl = r'(?:softlayer|sl|)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    username_keyword = r'(?:username|id|user|userid|user-id|user-name|name|user_id|user_name|uname)'
    opt_space = r'(?: |)'
    seperator = r'(?: |=|:|:=|=>)+'
    username = r'(\w(?:\w|_|@|\.|-)+)'
    regex = re.compile(
        r'{opt_quote}{opt_dashes}{opt_sl}{opt_dash_undrscr}{opt_api}{opt_dash_undrscr}'
        '{username_keyword}{opt_quote}{seperator}{opt_quote}{username}{opt_quote}'.format(
            opt_quote=opt_quote,
            opt_dashes=opt_dashes,
            opt_sl=opt_sl,
            opt_dash_undrscr=opt_dash_undrscr,
            opt_api=opt_api,
            username_keyword=username_keyword,
            opt_space=opt_space,
            username=username,
            seperator=seperator,
        ), flags=re.IGNORECASE,
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
