from __future__ import absolute_import

import requests

from .base import classproperty
from .base import RegexBasedDetector
from detect_secrets.core.constants import VerifiedResult


class IbmCloudIamDetector(RegexBasedDetector):
    """ Scans for IBM Cloud IAM credentials """

    secret_type = 'IBM Cloud IAM Key'

    # opt means optional
    opt_ibm_cloud_iam = r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|' + \
        r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-zA-Z0-9_\-]{44})'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=opt_ibm_cloud_iam + opt_dash_undrscr + opt_api,
            password_keyword_regex=key_or_pass,
            password_regex=secret,
        ),
    ]

    @classproperty
    def disable_flag_text(cls):
        return 'no-ibm-cloud-iam-scan'

    def verify(self, token, **kwargs):
        response = verify_cloud_iam_api_key(token)
        try:
            if response.status_code != 200:
                return VerifiedResult.UNVERIFIED

            if 'active' not in response.json():
                return VerifiedResult.UNVERIFIED

            if response.json()['active']:
                return VerifiedResult.VERIFIED_TRUE
            else:
                return VerifiedResult.VERIFIED_FALSE
        except requests.exceptions.RequestException:
            return VerifiedResult.UNVERIFIED


def verify_cloud_iam_api_key(apikey):  # pragma: no cover
    if type(apikey) == bytes:
        apikey = apikey.decode('UTF-8')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    response = requests.post(
        'https://iam.cloud.ibm.com/identity/introspect',
        headers=headers,
        data={
            'apikey': apikey,
        },
    )
    return response
