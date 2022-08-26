import re

import requests

from .base import RegexBasedDetector
from detect_secrets.constants import DEFAULT_GHE_INSTANCE
from detect_secrets.core.constants import VerifiedResult


class GheDetector(RegexBasedDetector):
    """ Scans for GitHub Enterprise credentials """

    secret_type = 'GitHub Enterprise Credentials'
    denylist = None

    def __init__(self, ghe_instance=DEFAULT_GHE_INSTANCE, *args, **kwargs):
        super(GheDetector, self).__init__(*args, **kwargs)
        self.ghe_instance = ghe_instance

        opt_github_prefix = r'(?:github|gh|ghe|git|auth|)(?:_|-|)(?:api|)'
        opt_space = r'(?: *)'
        opt_quote = r'(?:"|\'|)'
        header_keyword = r'(?:token|bearer|Basic)'
        credential_keywords = 'cred|creds|credentials|credential|cred'
        key_or_pass_values = 'key|pwd|password|pass|token|oauth|auth|pat|ghe|gh|secret'
        key_or_pass_misspelt = 'ky|pw|pasword|pas|tkn|ath|secert|secrete'
        key_or_pass = r'(?:{key_or_pass}|{credential_keywords}|{key_or_pass_misspelt})'\
            .format(
                key_or_pass=key_or_pass_values,
                credential_keywords=credential_keywords,
                key_or_pass_misspelt=key_or_pass_misspelt,
            )
        api_endpoint = r'(?:{ghe_instance}|api.{ghe_instance})'\
            .format(ghe_instance=self.ghe_instance)
        forty_hex = r'(?:(?<=\W)|(?<=^))([0-9a-f]{40})(?:(?=\W)|(?=$))'
        b64_encoded_token = r'(?:(?<=\W)|(?<=^))([A-Za-z0-9+/]{55}=)(?:(?=\W)|(?=$))'
        opt_username = r'(?:[a-zA-Z0-9-]+:|)'
        self.denylist = [
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
                    b64_encoded_token=b64_encoded_token,
                ), flags=re.IGNORECASE,
            ),
        ]

    def verify(self, token, *args, **kwargs):
        try:
            if type(token) == bytes:
                token = token.decode('UTF-8')
            headers = {'Authorization': 'token %s' % token}
            response = requests.get(f'https://{self.ghe_instance}/api/v3', headers=headers)
            if response.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif response.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            else:
                return VerifiedResult.UNVERIFIED
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED

    @property
    def __dict__(self):
        output = super(GheDetector, self).__dict__
        output.update({
            'ghe_instance': self.ghe_instance,
        })

        return output
