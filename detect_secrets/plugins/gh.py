from __future__ import absolute_import

import re

import requests

from .base import classproperty
from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class GHDetector(RegexBasedDetector):
    """ Scans for GitHub credentials """

    secret_type = 'GitHub Credentials'

    opt_github_prefix = r'(?:github|gh|ghe|git|)(?:_|-|)(?:api|)'
    opt_space = r'(?: *)'
    opt_quote = r'(?:"|\'|)'
    header_keyword = r'(?:token|bearer|Basic)'
    key_or_pass = r'(?:key|pwd|password|pass|token|oauth)'
    api_endpoint = r'(?:github.ibm.com|api.github.ibm.com)'
    forty_hex = r'(?:(?<=\W)|(?<=^))([0-9a-f]{40})(?:(?=\W)|(?=$))'
    b64_encoded_token = r'(?:(?<=\W)|(?<=^))([A-Za-z0-9+/]{55}=)(?:(?=\W)|(?=$))'
    opt_username = r'(?:[a-zA-Z0-9-]+:|)'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=opt_github_prefix,
            password_keyword_regex=key_or_pass,
            password_regex=forty_hex,
        ),
        re.compile(
            r'https://{opt_username}{forty_hex}@{api_endpoint}'.format(
                forty_hex=forty_hex,
                api_endpoint=api_endpoint,
                opt_username=opt_username,
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

    @classproperty
    def disable_flag_text(cls):
        return 'no-ghe-scan'

    def verify(self, token, **kwargs):
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
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED
