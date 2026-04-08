import os
from functools import lru_cache
from typing import cast

import requests

from ..constants import VerifiedResult
from ..core.plugins import Plugin
from ..settings import get_settings
from ..util.code_snippet import CodeSnippet
from ..util.inject import call_function_with_arguments
from .util import get_caller_path


def is_invalid_file(filename: str) -> bool:
    return not os.path.isfile(filename)


def is_baseline_file(filename: str) -> bool:
    """
    Checks if the given filename matches the baseline file.

    This normalizes both paths to handle cases like:
    - ./secrets.baseline vs secrets.baseline
    - ../dir/file.txt vs ../dir/file.txt
    - Paths with redundant separators (//, /./)
    """
    try:
        # Normalize both paths to absolute paths for accurate comparison
        normalized_filename = os.path.realpath(filename)
        normalized_baseline = os.path.realpath(_get_baseline_filename())
        return normalized_filename == normalized_baseline
    except (OSError, ValueError):
        # Fallback to basename comparison if path resolution fails
        return os.path.basename(filename) == os.path.basename(_get_baseline_filename())


@lru_cache(maxsize=1)
def _get_baseline_filename() -> str:
    path = get_caller_path(offset=1)
    return cast(str, get_settings().filters[path]['filename'])


def is_ignored_due_to_verification_policies(
    secret: str,
    plugin: Plugin,
    context: CodeSnippet,
) -> bool:
    """
    Valid policies include:
        - Only VERIFIED_TRUE
        - Can be UNVERIFIED or VERIFIED_TRUE
        - Disabled check.

    There's no such thing as "only verified false", because if you're going to verify
    something, and it's verified false, why are you still including it as a valid secret?
    """
    try:
        verify_result = call_function_with_arguments(
            plugin.verify,
            secret=secret,
            context=context,
        )
    except requests.exceptions.RequestException:
        verify_result = VerifiedResult.UNVERIFIED

    if not verify_result:
        return False

    if verify_result.value < _get_verification_policy().value:
        return True

    return False


@lru_cache(maxsize=1)
def _get_verification_policy() -> VerifiedResult:
    path = get_caller_path(offset=1)
    return VerifiedResult(get_settings().filters[path]['min_level'])
