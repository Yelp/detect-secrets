"""
This plugin searches each line with a set of regexes.
"""
from __future__ import absolute_import

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


class RegexBasedDetector(BasePlugin):
    """Base class for regular-expressed based detectors.

    Replace `secret_type` with a description and `blacklist`
    with a sequence of regular expressions.
    """
    secret_type = 'Regex'
    blacklist = ()

    def analyze_string(self, string, line_num, filename):
        output = {}

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
        for regex in self.blacklist:
            if regex.search(string):
                yield regex.pattern
