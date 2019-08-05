"""
This plugin searches for Mailchimp keys
"""
from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class MailchimpDetector(RegexBasedDetector):

    secret_type = 'Mailchimp Access Key'

    denylist = (
        # Mailchimp key
        re.compile(r'[0-9a-z]{32}(-us[0-9]{1,2})'),
    )
