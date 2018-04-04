from __future__ import absolute_import

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


BLACKLIST = (
    'BEGIN RSA PRIVATE KEY',
    'BEGIN DSA PRIVATE KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'BEGIN PRIVATE KEY',
)


class PrivateKeyDetector(BasePlugin):
    """This checks for private keys by determining whether the blacklisted
    lines are present in the analyzed string.

    This is based off https://github.com/pre-commit/pre-commit-hooks.
    """

    secret_type = 'Private Key'

    def analyze(self, file, filename):
        """We override this, because we're only looking at the first line.

        Though this doesn't strictly follow the schema of the parent function,
        all that really matters is that each secret within this file scanned
        has a unique key. Since we're only expecting at most one secret from
        this file, by definition any key is a unique key, so we good.
        """
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
