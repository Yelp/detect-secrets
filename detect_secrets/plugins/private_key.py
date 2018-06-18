"""
This code was extracted in part from
https://github.com/pre-commit/pre-commit-hooks. Using similar heuristic logic,
we adapt it to fit our plugin infrastructure, to create an organized,
concerted effort in detecting all type of secrets in code.

Copyright (c) 2014 pre-commit dev team: Anthony Sottile, Ken Struys

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

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


BLACKLIST = (
    'BEGIN RSA PRIVATE KEY',
    'BEGIN DSA PRIVATE KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'BEGIN PRIVATE KEY',
    'PuTTY-User-Key-File-2',
    'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
)


class PrivateKeyDetector(BasePlugin):
    """This checks for private keys by determining whether the blacklisted
    lines are present in the analyzed string.
    """

    secret_type = 'Private Key'

    def analyze(self, file, filename):
        """We override this, because we're only looking at the first line.

        :param file:     The File object itself.
        :param filename: string; filename of File object, used for creating
                         PotentialSecret objects
        :returns         dictionary representation of set (for random access by hash)
                         { detect_secrets.core.potential_secret.__hash__:
                               detect_secrets.core.potential_secret         }
        """

        return self.analyze_string(
            file.readline(),
            1,
            filename,
        )

    def analyze_string(self, string, line_num, filename):
        output = {}

        if any(line in string for line in BLACKLIST):
            secret = PotentialSecret(
                self.secret_type,
                filename,
                line_num,
                string,
            )
            output[secret] = secret

        return output
