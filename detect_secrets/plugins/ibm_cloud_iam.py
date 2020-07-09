import requests

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector


class IbmCloudIamDetector(RegexBasedDetector):
    """Scans for IBM Cloud IAM Key."""

    secret_type = 'IBM Cloud IAM Key'

    # opt means optional
    opt_ibm_cloud_iam = r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|' + \
        r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-zA-Z0-9_\-]{44}(?![a-zA-Z0-9_\-]))'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=opt_ibm_cloud_iam + opt_dash_undrscr + opt_api,
            secret_keyword_regex=key_or_pass,
            secret_regex=secret,
        ),
    ]

    def verify(self, token, **kwargs):
        response = verify_cloud_iam_api_key(token)

        return VerifiedResult.VERIFIED_TRUE if response.status_code == 200 \
            else VerifiedResult.VERIFIED_FALSE


def verify_cloud_iam_api_key(apikey):  # pragma: no cover
    if type(apikey) == bytes:
        apikey = apikey.decode('UTF-8')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    response = requests.post(
        'https://iam.cloud.ibm.com/identity/token',
        headers=headers,
        data={
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': apikey,
        },
    )
    return response
