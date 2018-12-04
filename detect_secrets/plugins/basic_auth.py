from __future__ import absolute_import

import re

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


SPECIAL_URL_CHARACTERS = ':/?#[]@'
BASIC_AUTH_REGEX = re.compile(
    r'://[^{}\s]+:([^{}\s]+)@'.format(
        re.escape(SPECIAL_URL_CHARACTERS),
        re.escape(SPECIAL_URL_CHARACTERS),
    ),
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
