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
import os
import re
from typing import Any
from typing import Generator
from typing import Optional
from typing import Set
from typing import Tuple

from ..core.potential_secret import PotentialSecret
from ..util.code_snippet import CodeSnippet
from .base import RegexBasedDetector


class PrivateKeyDetector(RegexBasedDetector):
    """
    Scans for private keys.

    This checks for private keys by determining whether the denylisted
    lines are present in the analyzed string.
    """

    secret_type = 'Private Key'
    MAX_FILE_SIZE: int = 8 * 1024

    begin_key_opening = r'(?P<begin_key>BEGIN'
    key_types = r'(?: DSA | EC | OPENSSH | PGP | RSA | SSH2 ENCRYPTED | )'
    begin_key_closing = r'PRIVATE KEY-*)'
    begin_key = fr'{begin_key_opening}{key_types}{begin_key_closing}'
    secret_key = r'(?P<secret_key>[A-Za-z0-9+\/\\\n]{10,}={0,3})'
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

    def __init__(self) -> None:
        self._analyzed_files: Set[str] = set()
        self._commit_hashes: Set[Tuple[str, str]] = set()

    def analyze_line(
            self,
            filename: str,
            line: str,
            line_number: int = 0,
            context: Optional[CodeSnippet] = None,
            raw_context: Optional[CodeSnippet] = None,
            commit_hash: Optional[str] = '',
            **kwargs: Any,
    ) -> Set[PotentialSecret]:
        output: Set[PotentialSecret] = set()

        output.update(
            super().analyze_line(
                filename=filename, line=line, line_number=line_number,
                context=context, raw_context=raw_context, **kwargs,
            ),
        )

        if output:
            return output

        # for git history
        if commit_hash:
            if (filename, commit_hash) not in self._commit_hashes:
                file_content = ''
                for file_line in context.lines:  # type: ignore
                    file_content += file_line
                found_secrets = super().analyze_line(
                    filename=filename, line=file_content, line_number=1,
                    context=context, raw_context=raw_context, **kwargs,
                )
                updated_secrets = self._get_updated_secrets(
                    found_secrets=found_secrets,
                    file_content=file_content,
                    split_by_newline=True,
                )
                output.update(updated_secrets)
                self._commit_hashes.add((filename, commit_hash))
            return output

        if filename not in self._analyzed_files \
                and 0 < self.get_file_size(filename) < PrivateKeyDetector.MAX_FILE_SIZE:
            self._analyzed_files.add(filename)
            file_content = self.read_file(filename)
            if file_content:
                found_secrets = super().analyze_line(
                    filename=filename, line=file_content, line_number=1,
                    context=context, raw_context=raw_context, **kwargs,
                )
                updated_secrets = self._get_updated_secrets(
                    found_secrets=found_secrets,
                    file_content=file_content,
                )
                output.update(updated_secrets)
        return output

    def _get_updated_secrets(
        self, found_secrets: Set[PotentialSecret],
        file_content: str,
        split_by_newline: Optional[bool] = False,
    ) -> Set[PotentialSecret]:
        updated_secrets: Set[PotentialSecret] = set()
        for sec in found_secrets:
            secret_val = sec.secret_value.strip() or ''  # type: ignore
            if split_by_newline and '\n' in secret_val:
                secret_val = secret_val.split('\n')[0]
            line_number = self.find_line_number(file_content, secret_val)
            updated_secrets.add(
                PotentialSecret(
                    type=self.secret_type,
                    filename=sec.filename,
                    secret=secret_val,
                    line_number=line_number,
                    is_verified=sec.is_verified,
                ),
            )
        return updated_secrets

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

    def read_file(self, file_path: str) -> str:
        try:
            with open(file_path) as f:
                file_content = f.read()
                return file_content
        except Exception:
            return ''

    def get_file_size(self, file_path: str) -> int:
        try:
            return os.path.getsize(file_path)
        except Exception:
            return -1

    def find_line_number(
            self, file_content: str, substring: str, default_line_number: int = 1,
    ) -> int:
        if len(substring) == 0:
            return default_line_number
        lines = file_content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            if substring in line:
                return line_number
        return default_line_number
