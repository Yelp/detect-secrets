from __future__ import absolute_import

import re

from .base import RegexBasedDetector
from detect_secrets.plugins.gh import GHDetector


class GHDetectorV2(RegexBasedDetector):
    """ Tighter version of GHDetector. """

    secret_type = 'GitHub Credentials V2'
    opt_github = r'(?:github|gh|ghe|git|)'
    opt_space = r'(?: |)'
    opt_quote = r'(?:"|\'|)'
    opt_assignment = r'(?:=|:|:=|=>|)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    header_keyword = r'(?:token|bearer|Basic)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    api_endpoint = r'(?:github.ibm.com|api.github.ibm.com)'
    forty_hex = r'(?:(?<=\W)|(?<=^))([0-9a-f]{40})(?:(?=\W)|(?=$))'
    b64_encoded_token = r'(?:(?<=\W)|(?<=^))([A-Za-z0-9+/]{55}=)(?:(?=\W)|(?=$))'
    denylist = [
        re.compile(
            r'{opt_quote}{opt_github}{opt_dash_undrscr}{opt_api}{opt_dash_undrscr}{key_or_pass}'
            '{opt_quote}{opt_space}{opt_assignment}{opt_space}{opt_quote}{forty_hex}'
            '{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_github=opt_github,
                opt_dash_undrscr=opt_dash_undrscr,
                opt_api=opt_api,
                key_or_pass=key_or_pass,
                opt_space=opt_space,
                opt_assignment=opt_assignment,
                forty_hex=forty_hex,
            ), flags=re.IGNORECASE,
        ),
        re.compile(
            r'https://\w+:{forty_hex}@{api_endpoint}'.format(
                forty_hex=forty_hex,
                api_endpoint=api_endpoint,
            ), flags=re.IGNORECASE,
        ),
        re.compile(
            r'{opt_quote}Authorization{opt_quote}{opt_space}:{opt_space}{opt_quote}'
            '{header_keyword}{opt_space}{forty_hex}{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_space=opt_space,
                header_keyword=header_keyword,
                forty_hex=forty_hex,
            ), flags=re.IGNORECASE,
        ),
        re.compile(
            r'{opt_quote}Authorization{opt_quote}{opt_space}:{opt_space}{opt_quote}'
            'Basic{opt_space}{b64_encoded_token}{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_space=opt_space,
                header_keyword=header_keyword,
                b64_encoded_token=b64_encoded_token,
            ), flags=re.IGNORECASE,
        ),
    ]

    def verify(self, token):
        return GHDetector().verify(token)
