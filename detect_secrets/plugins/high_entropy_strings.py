from __future__ import absolute_import

import math
import re
import string

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


class HighEntropyStringsPlugin(BasePlugin):
    """Base class for string pattern matching"""

    secret_type = 'High Entropy String'

    def __init__(self, charset, limit, *args):
        self.charset = charset
        self.entropy_limit = limit
        self.regex = re.compile(r'([\'"])([%s]+)(\1)' % charset)

        # Allow whitelisting individual lines.
        # TODO: Update for not just python comments?
        self.ignore_regex = re.compile(r'# ?pragma: ?whitelist[ -]secret')

    def calculate_shannon_entropy(self, data):
        """Returns the entropy of a given string.

        Borrowed from: http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html.

        :param string:  string. The word to analyze.
        :param charset: string. The character set from which to calculate entropy.
        :returns:       float, between 0.0 and 8.0
        """
        if not data:  # pragma: no cover
            return 0

        entropy = 0
        for x in self.charset:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        return entropy

    def analyze_string(self, string, line_num, filename):
        """Searches string for custom pattern, and captures all high entropy strings that
        match self.regex, with a limit defined as self.entropy_limit."""

        output = {}

        if self.ignore_regex.search(string):
            return output

        # There may be multiple strings on the same line
        results = self.regex.findall(string)
        for result in results:
            entropy_value = self.calculate_shannon_entropy(result[1])
            if entropy_value > self.entropy_limit:
                secret = PotentialSecret(self.secret_type, filename, line_num, result[1])
                output[secret] = secret

        return output

    @property
    def __dict__(self):
        output = super(HighEntropyStringsPlugin, self).__dict__
        output.update({
            'limit': self.entropy_limit,
        })

        return output


class HexHighEntropyString(HighEntropyStringsPlugin):
    """HighEntropyStringsPlugin for hex strings"""

    def __init__(self, limit, *args):
        super(HexHighEntropyString, self).__init__(string.hexdigits, limit)


class Base64HighEntropyString(HighEntropyStringsPlugin):
    """HighEntropyStringsPlugin for base64 encoded strings"""

    def __init__(self, limit, *args):
        super(Base64HighEntropyString, self).__init__(
            string.ascii_letters + string.digits + '+/=',
            limit
        )
