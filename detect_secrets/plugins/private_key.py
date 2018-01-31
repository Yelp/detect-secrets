#!/usr/bin/python
from __future__ import absolute_import

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


BLACKLIST = [
    'BEGIN RSA PRIVATE KEY',
    'BEGIN DSA PRIVATE KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'BEGIN PRIVATE KEY',
]


class PrivateKeyPlugin(BasePlugin):
    """This checks for private keys by determining whether the blacklisted
    lines are present in the analyzed string.

    This is based off https://github.com/pre-commit/pre-commit-hooks.
    """

    def __init__(self):
        self.secret_type = 'Private Key'

    def analyze(self, file, filename):
        """We override this, because we're only looking at the first line."""
        return self.analyze_string(
            file.readline(),
            1,
            filename,
        )

    def analyze_string(self, string, line_num, filename):
        output = {}

        if any(line in string for line in BLACKLIST):
            output[filename] = PotentialSecret(
                self.secret_type,
                filename,
                line_num,
                string,
            )

        return output
