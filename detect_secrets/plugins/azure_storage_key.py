"""
This plugin searches for Azure Storage Account access keys.
"""
from __future__ import annotations

import re
from typing import Any
from typing import List
from typing import Optional
from typing import Set

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.util.code_snippet import CodeSnippet


class AzureStorageKeyDetector(RegexBasedDetector):
    """Scans for Azure Storage Account access keys."""
    secret_type = 'Azure Storage Account access key'

    account_key = 'AccountKey'
    azure = 'azure'

    max_line_length = 4000
    max_part_length = 2000
    integrity_regex = re.compile(r'integrity[:=]')

    denylist = [
        # Account Key (AccountKey=xxxxxxxxx)
        re.compile(
            r'(?:["\']?[A-Za-z0-9+\/]{86,1000}==["\']?)',
        ),
    ]

    context_keys = [
        r'{account_key}=\s*{secret}',

        # maximum 2 lines secret distance under azure mention (case-insensitive)
        r'(?i)\b{azure}(.*\n){{0,2}}.*{secret}',

        # maximum 2 lines secret distance above azure mention (case-insensitive)
        r'(?i)\b{secret}(.*\n){{0,2}}.*{azure}',
    ]

    def analyze_line(
            self,
            filename: str,
            line: str,
            line_number: int = 0,
            context: Optional[CodeSnippet] = None,
            raw_context: Optional[CodeSnippet] = None,
            **kwargs: Any,
    ) -> Set[PotentialSecret]:
        output: Set[PotentialSecret] = set()
        results = super().analyze_line(
            filename=filename, line=line, line_number=line_number,
            context=context, raw_context=raw_context, **kwargs,
        )
        output.update(self.analyze_context_keys(results, context, line))

        return output

    def analyze_context_keys(
            self,
            results: Set[PotentialSecret],
            context: Optional[CodeSnippet],
            line: str,
    ) -> List[PotentialSecret]:
        context_text = '\n'.join(context.lines).replace('\n\n', '\n') if context else line
        return [result for result in results if self.context_keys_exists(result, context_text)]

    def context_keys_exists(self, result: PotentialSecret, string: str) -> bool:
        if len(string) > self.max_line_length:
            # for very long lines, we don't run the regex to avoid performance issues
            return False
        if result.secret_value:
            for secret_regex in self.context_keys:
                regex = re.compile(
                    secret_regex.format(
                        secret=re.escape(result.secret_value), account_key=self.account_key,
                        azure=self.azure,
                    ), re.MULTILINE,
                )
                if regex.pattern.startswith(self.account_key) and self.account_key not in string:
                    continue
                if self.azure in regex.pattern.lower() and self.azure not in string.lower():
                    continue
                if self.contains_integrity(result.secret_value, string):
                    continue
                if regex.search(string) is not None:
                    return True
        return False

    def contains_integrity(self, secret_val: str, string: str) -> bool:
        # we want to ignore cases of lock files which contains hashes
        context_parts = string.split('\n')
        return any(
            len(part) < self.max_part_length and
            secret_val in part and
            self.integrity_regex.search(part) is not None for part in context_parts
        )
