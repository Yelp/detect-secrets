import os
from functools import lru_cache

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
