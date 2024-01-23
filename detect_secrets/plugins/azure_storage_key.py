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

    denylist = [
        # Account Key (AccountKey=xxxxxxxxx)
        re.compile(
            r'(?:["\']?[A-Za-z0-9+\/]{86,1000}==["\']?)$',
        ),
    ]

    skip_keys = [
        r'PublicKey[s]?:[a-z-\s\n>]*{secret}',
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
        output.update(self.filter_skip_keys(results, context, line))

        return output

    def filter_skip_keys(
            self,
            results: Set[PotentialSecret],
            context: Optional[CodeSnippet],
            line: str,
    ) -> List[PotentialSecret]:
        context_text = ''.join(context.lines) if context else line
        return [result for result in results if not self.skip_keys_exists(result, context_text)]

    def skip_keys_exists(self, result: PotentialSecret, string: str) -> bool:
        if result.secret_value:
            for secret_regex in self.skip_keys:
                regex = re.compile(
                    secret_regex.format(
                        secret=re.escape(result.secret_value),
                    ), re.DOTALL,
                )
                if regex.search(string) is not None:
                    return True
        return False
