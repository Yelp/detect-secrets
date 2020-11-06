import os
import time
from typing import Any
from typing import Dict
from typing import List

from ..__version__ import VERSION
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util import git
from ..util.path import get_relative_path_if_in_cwd
from .log import log
from .secrets_collection import SecretsCollection


def create(path: str, should_scan_all_files: bool = False) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    secrets = SecretsCollection()

    files = _get_files_to_scan(path, should_scan_all_files)
    for filename in files:
        secrets.scan_file(filename)

    return secrets


def _get_files_to_scan(root: str, should_scan_all_files: bool) -> List[str]:
    output: List[str] = []
    if not should_scan_all_files:
        valid_paths = git.get_tracked_files(root)
        if not valid_paths:
            log.warning('Did not detect git repository. Try scanning all files instead.')
            return output

    for path_root, _, filenames in os.walk(root):
        for filename in filenames:
            path = get_relative_path_if_in_cwd(os.path.join(path_root, filename))
            if not path:
                # e.g. symbolic links may be pointing outside the root directory
                continue

            if (
                not should_scan_all_files
                and path not in valid_paths
            ):
                # Not a git-tracked file
                continue

            output.append(path)

    return output


def load(baseline: Dict[str, Any], filename: str) -> SecretsCollection:
    """
    With a given baseline file, load all settings and discovered secrets from it.

    :raises: KeyError
    """
    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def format_for_output(secrets: SecretsCollection) -> Dict[str, Any]:
    return {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'version': VERSION,
        'results': secrets.json(),

        # This will populate settings of filters and plugins,
        **get_settings().json(),
    }
