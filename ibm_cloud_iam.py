from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class IBMCloudIAMDetector(RegexBasedDetector):

    secret_type = 'IBM Cloud IAM Key'

    # opt means optional
    opt_quote = r'(?:"|\'|)'
    opt_dashes = r'(?:--|)'
    ibm_cloud_iam = r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|' + \
                    r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    opt_space = r'(?: *)'
    opt_assignment = r'(?:=|:|:=|=>|)'
    secret = r'([a-zA-z0-9_\-]{44})'
    denylist = [
        re.compile(
            r'{opt_quote}{opt_dashes}{ibm_cloud_iam}{opt_dash_undrscr}{opt_api}{opt_dash_undrscr}'
            '{key_or_pass}{opt_quote}{opt_space}{opt_assignment}{opt_space}{opt_quote}'
            '{secret}{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_dashes=opt_dashes,
                ibm_cloud_iam=ibm_cloud_iam,
                opt_dash_undrscr=opt_dash_undrscr,
                opt_api=opt_api,
                key_or_pass=key_or_pass,
                opt_space=opt_space,
                opt_assignment=opt_assignment,
                secret=secret,
            ), flags=re.IGNORECASE,
        ),
    ]
