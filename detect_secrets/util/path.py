import os
from typing import Optional


def get_relative_path_if_in_cwd(path: str) -> Optional[str]:
    filepath = os.path.realpath(path)[len(os.getcwd() + '/'):]
    if os.path.isfile(filepath):
        return filepath

    return None
