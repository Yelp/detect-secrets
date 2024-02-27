"""
This code was extracted in part from
https://github.com/pre-commit/pre-commit-hooks. Using similar heuristic logic,
we adapted it to fit our plugin infrastructure, to create an organized,
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
import re
from typing import Generator

from .base import RegexBasedDetector


class PrivateKeyDetector(RegexBasedDetector):
    """
    Scans for private keys.

    This checks for private keys by determining whether the denylisted
    lines are present in the analyzed string.
    """

    secret_type = 'Private Key'

    begin_key_opening = r'(?P<begin_key>BEGIN'
    key_types = r'(?: DSA | EC | OPENSSH | PGP | RSA | SSH2 ENCRYPTED | )'
    begin_key_closing = r'PRIVATE KEY-*)'
    begin_key = fr'{begin_key_opening}{key_types}{begin_key_closing}'
    secret_key = r'(?P<secret_key>[A-Za-z0-9+\/\\\n]*={0,3})?'
    end_key = r'(?P<end_key>\n*-*END)?'

    denylist = [
        re.compile(
            r'{begin_key}{secret_key}{end_key}'.format(
                begin_key=begin_key,
                secret_key=secret_key,
                end_key=end_key,
            ),
        ),
        re.compile(r'PuTTY-User-Key-File-2'),
    ]

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for regex in self.denylist:
            for match in regex.findall(string):
                if isinstance(match, tuple):
                    begin_key, secret_key, end_key = match
                    if begin_key:
                        yield secret_key if secret_key else begin_key
                else:
                    # only PuTTY-User-Key-File should not be a tuple
                    yield match
