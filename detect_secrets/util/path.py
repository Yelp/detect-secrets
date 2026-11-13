import os
from pathlib import Path
from typing import Optional


def get_relative_path(root: str, path: str) -> Optional[str]:
    if Path(os.getcwd()) == Path(root):
        return get_relative_path_if_in_cwd(path)

    return os.path.realpath(path)[len(root + '/'):]


def get_relative_path_if_in_cwd(path: str) -> Optional[str]:
    real_path = os.path.realpath(path)
    if not os.path.isfile(real_path):
        return None

    try:
        rel = Path(real_path).relative_to(Path.cwd().resolve())
        return str(rel)
    except ValueError:
        return real_path


def convert_local_os_path(path: str) -> str:
    # Linux filesystem, replace \\ with /
    if os.sep == '/':
        path = path.replace('\\', '/')
        return path
    else:
        path = path.replace('/', '\\')
        return path
