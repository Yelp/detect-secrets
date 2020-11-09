import os
from functools import lru_cache

from ..constants import VerifiedResult
from ..core.plugins import Plugin
from ..settings import get_settings
from .util import get_caller_path


def is_invalid_file(filename: str) -> bool:
    return not os.path.isfile(filename)


def is_baseline_file(filename: str) -> bool:
    return filename == _get_baseline_filename()


@lru_cache(maxsize=1)
def _get_baseline_filename() -> str:
    path = get_caller_path(offset=1)
    return get_settings().filters[path]['filename']


def is_ignored_due_to_verification_policies(secret: str, plugin: Plugin) -> bool:
    """
    Valid policies include:
        - Only VERIFIED_TRUE
        - Can be UNVERIFIED or VERIFIED_TRUE
        - Disabled check.

    There's no such thing as "only verified false", because if you're going to verify
    something, and it's verified false, why are you still including it as a valid secret?
    """
    verify_result = plugin.verify(secret)
    if verify_result.value < _get_verification_policy().value:
        return True

    return False


@lru_cache(maxsize=1)
def _get_verification_policy() -> VerifiedResult:
    path = get_caller_path(offset=1)
    return VerifiedResult(get_settings().filters[path]['min_level'])
