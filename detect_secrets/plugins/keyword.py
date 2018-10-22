"""
This code was extracted in part from
https://github.com/PyCQA/bandit. Using similar heuristic logic,
we adapted it to fit our plugin infrastructure, to create an organized,
concerted effort in detecting all type of secrets in code.

Copyright (c) 2014 Hewlett-Packard Development Company, L.P.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
from __future__ import absolute_import

import re

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.core.constants import WHITELIST_REGEX


# Note: All values here should be lowercase
BLACKLIST = (
    'apikey',
    'api_key',
    'pass',
    'password',
    'passwd',
    'private_key',
    'secret',
    'secrete',
    'token',
)
# Uses lazy quantifiers
BLACKLIST_REGEX = re.compile(
    # Followed by double-quotes and a semi-colon
    # e.g. private_key "something";
    # e.g. private_key 'something';
    r'|'.join(
        '{}(.*?)("|\')(\\S*?)(\'|");'.format(
            value,
        )
        for value in BLACKLIST
    ) + '|' +
    # Followed by a :
    # e.g. token:
    r'|'.join(
        '{}:'.format(
            value,
        )
        for value in BLACKLIST
    ) + '|' +
    # Follwed by an = sign
    # e.g. my_password =
    r'|'.join(
        '{}(.*?)='.format(
            value,
        )
        for value in BLACKLIST
    ) +
    # For `pwd` it has to start with pwd after whitespace, it is too common
    '|\\spwd(.*?)=',
)


class KeywordDetector(BasePlugin):
    """This checks if blacklisted keywords
    are present in the analyzed string.
    """

    secret_type = 'Password'

    def analyze_string(self, string, line_num, filename):
        output = {}

        if WHITELIST_REGEX.search(string):
            return output

        for identifier in self.secret_generator(string):
            secret = PotentialSecret(
                self.secret_type,
                filename,
                identifier,
                line_num,
            )
            output[secret] = secret

        return output

    def secret_generator(self, string):
        match = BLACKLIST_REGEX.search(
            string.lower(),
        )
        if not match:
            return []
        return [match.group()]
