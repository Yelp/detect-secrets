from __future__ import absolute_import

import re

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


BASIC_AUTH_REGEX = re.compile(
    r'://[^:]+:([^@]+)@',
)


class BasicAuthDetector(BasePlugin):

    secret_type = 'Basic Auth Credentials'

    def analyze_string(self, string, line_num, filename):
        output = {}

        for result in self.secret_generator(string):
            secret = PotentialSecret(
                self.secret_type,
                filename,
                result,
                line_num,
            )
            output[secret] = secret

        return output

    def secret_generator(self, string):
        results = BASIC_AUTH_REGEX.findall(string)
        for result in results:
            yield result
