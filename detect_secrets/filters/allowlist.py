import os
import re
from functools import lru_cache
from typing import Dict
from typing import List
from typing import Pattern

from ..util.code_snippet import CodeSnippet


def is_line_allowlisted(filename: str, line: str, context: CodeSnippet) -> bool:
    regexes = _get_allowlist_regexes()

    _, ext = os.path.splitext(filename)
    if ext[1:] in _get_file_based_allowlist_regexes():
        regexes = _get_file_based_allowlist_regexes()[ext[1:]]

    for regex in regexes:
        if regex.search(line):
            return True

    previous_line = context.previous_line
    regexes = _get_allowlist_nextline_regexes()

    if ext[1:] in _get_file_based_allowlist_nextline_regexes():
        regexes = _get_file_based_allowlist_nextline_regexes()[ext[1:]]

    for regex in regexes:
        if regex.search(previous_line):
            return True

    return False


@lru_cache(maxsize=1)
def _get_file_based_allowlist_regexes() -> Dict[str, List[Pattern]]:
    # Add to this mapping (and ALLOWLIST_REGEXES if applicable) lazily,
    # as more language specific file parsers are implemented.
    # Discussion: https://github.com/Yelp/detect-secrets/pull/105
    return {
        'yaml': [_get_allowlist_regexes()[0]],
    }


@lru_cache(maxsize=1)
def _get_allowlist_regexes() -> List[Pattern]:
    return [
        re.compile(r)
        for r in [
            # Note: Always use allowlist, whitelist will be deprecated in the future
            r'[ \t]+{} *pragma: ?(allow|white)list[ -]secret.*?{}[ \t]*$'.format(start, end)
            for start, end in (
                ('#', ''),                    # e.g. python or yaml
                ('//', ''),                   # e.g. golang
                (r'/\*', r' *\*/'),           # e.g. c
                ('\'', ''),                   # e.g. visual basic .net
                ('--', ''),                   # e.g. sql
                (r'<!--[# \t]*?', ' *?-->'),  # e.g. xml
                # many other inline comment syntaxes are not included,
                # because we want to be performant for
                # any(regex.search(line) for regex in ALLOWLIST_REGEXES)
                # calls. of course, this won't be a concern if detect-secrets
                # switches over to implementing file plugins for each supported
                # filetype.
            )
        ]
    ]


@lru_cache(maxsize=1)
def _get_file_based_allowlist_nextline_regexes() -> Dict[str, List[Pattern]]:
    # Add to this mapping (and ALLOWLIST_REGEXES if applicable) lazily,
    # as more language specific file parsers are implemented.
    # Discussion: https://github.com/Yelp/detect-secrets/pull/105
    return {
        'yaml': [_get_allowlist_nextline_regexes()[0]],
    }


@lru_cache(maxsize=1)
def _get_allowlist_nextline_regexes() -> List[Pattern]:
    return [
        re.compile(r)
        for r in [
            r'^[ \t]*{} *pragma: ?allowlist[ -]nextline[ -]secret.*?{}[ \t]*$'.format(start, end)
            for start, end in (
                ('#', ''),                    # e.g. python or yaml
                ('//', ''),                   # e.g. golang
                (r'/\*', r' *\*/'),           # e.g. c
                ('\'', ''),                   # e.g. visual basic .net
                ('--', ''),                   # e.g. sql
                (r'<!--[# \t]*?', ' *?-->'),  # e.g. xml
                # many other inline comment syntaxes are not included,
                # because we want to be performant for
                # any(regex.search(line) for regex in ALLOWLIST_REGEXES)
                # calls. of course, this won't be a concern if detect-secrets
                # switches over to implementing file plugins for each supported
                # filetype.
            )
        ]
    ]
