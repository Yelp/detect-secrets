from __future__ import absolute_import

import re

from .base import RegexBasedDetector


class SoftLayerDetector(RegexBasedDetector):

    secret_type = 'SoftLayer Credentials'

    # opt means optional
    opt_quote = r'(?:"|)'
    opt_dashes = r'(?:--|)'
    sl = r'(?:softlayer|sl)'
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass)'
    opt_space = r'(?: |)'
    opt_equals = r'(?:=|:|:=|=>|)'
    secret = r'([a-z0-9]{64})'
    denylist = [
        re.compile(
            r'{opt_quote}{opt_dashes}{sl}{opt_dash_undrscr}{opt_api}{opt_dash_undrscr}{key_or_pass}'
            '{opt_quote}{opt_space}{opt_equals}{opt_space}{opt_quote}{secret}{opt_quote}'.format(
                opt_quote=opt_quote,
                opt_dashes=opt_dashes,
                sl=sl,
                opt_dash_undrscr=opt_dash_undrscr,
                opt_api=opt_api,
                key_or_pass=key_or_pass,
                opt_space=opt_space,
                opt_equals=opt_equals,
                secret=secret,
            ), flags=re.IGNORECASE,
        ),
        re.compile(
            r'(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})',
            flags=re.IGNORECASE,
        ),
    ]
