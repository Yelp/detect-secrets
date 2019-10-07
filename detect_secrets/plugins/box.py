from __future__ import absolute_import

from .base import RegexBasedDetector


class BoxDetector(RegexBasedDetector):

    secret_type = 'Box Credentials'

    token_prefix = r'(?:client)'
    password_keyword = r'(?:secret)'
    password = r'([a-zA-Z0-9]{32})'
    denylist = (
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=token_prefix,
            password_keyword_regex=password_keyword,
            password_regex=password,
        ),
    )
