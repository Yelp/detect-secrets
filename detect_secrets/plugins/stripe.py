"""
This plugin searches for Stripe keys
"""
from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class StripeDetector(RegexBasedDetector):

    secret_type = 'Stripe Access Key'

    denylist = (
        # stripe standard keys begin with sk_live and restricted with rk_live
        re.compile(r'(r|s)k_live_[0-9a-zA-Z]{24}'),
    )
