"""
This plugin searches for Mailchimp keys
"""
import re
from base64 import b64encode

import requests

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.base import RegexBasedDetector


class MailchimpDetector(RegexBasedDetector):
    """Scans for Mailchimp keys."""
    secret_type = 'Mailchimp Access Key'

    denylist = (
        re.compile(r'[0-9a-z]{32}-us[0-9]{1,2}'),
    )

    def verify(self, token, **kwargs):  # pragma: no cover
        _, datacenter_number = token.split('-us')

        response = requests.get(
            'https://us{}.api.mailchimp.com/3.0/'.format(
                datacenter_number,
            ),
            headers={
                'Authorization': b'Basic ' + b64encode(
                    'any_user:{}'.format(token).encode('utf-8'),
                ),
            },
        )
        return (
            VerifiedResult.VERIFIED_TRUE
            if response.status_code == 200
            else VerifiedResult.VERIFIED_FALSE
        )
