import json
import os
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util import git
from ..util.importlib import import_modules_from_package
from ..util.path import get_relative_path_if_in_cwd
from ..util.semver import Version
from .log import log
from .secrets_collection import SecretsCollection


def create(*paths: str, should_scan_all_files: bool = False) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    secrets = SecretsCollection()

    for path in paths:
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
    # This is required for backwards compatibility, and supporting upgrades from older versions.
    baseline = upgrade(baseline)

    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def load_from_file(filename: str) -> Dict[str, Any]:
    """
    :raises: UnableToReadBaselineError
    :raises: InvalidBaselineError
    """
    try:
        with open(filename) as f:
            return json.loads(f.read())
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise UnableToReadBaselineError from e


def format_for_output(secrets: SecretsCollection) -> Dict[str, Any]:
    return {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'version': VERSION,

        # This will populate settings of filters and plugins,
        **get_settings().json(),

        'results': secrets.json(),
    }


def save_to_file(
    secrets: Union[SecretsCollection, Dict[str, Any]],
    filename: str,
) -> None:    # pragma: no cover
    """
    :param secrets: if this is a SecretsCollection, it will output the baseline in its latest
        format. Otherwise, you should pass in a dictionary to this function, to manually
        specify the baseline format to save as.

        If you're trying to decide the difference, ask yourself whether there are any changes
        that does not directly impact the results of the scan.
    """
    output = secrets
    if isinstance(secrets, SecretsCollection):
        output = format_for_output(secrets)

    with open(filename, 'w') as f:
        f.write(json.dumps(output, indent=2) + '\n')


def upgrade(baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Baselines will eventually require format changes. This function is responsible for upgrading
    an older baseline to the latest version.
    """
    baseline_version = Version(baseline['version'])
    if baseline_version >= Version(VERSION):
        return baseline

    modules = import_modules_from_package(
        upgrades,
        filter=lambda x: not _is_relevant_upgrade_module(baseline_version)(x),
    )

    new_baseline = {**baseline}
    for module in modules:
        module.upgrade(new_baseline)

    new_baseline['version'] = VERSION
    return new_baseline


def _is_relevant_upgrade_module(current_version: Version) -> Callable:
    def wrapped(module_path: str) -> bool:
        # This converts `v1_0` to `1.0`
        affected_version_string = module_path.rsplit('.', 1)[-1].lstrip('v').replace('_', '.')

        # Patch version doesn't matter, because patches should not require baseline bumps.
        affected_version = Version(f'{affected_version_string}.0')

        return current_version < affected_version

    return wrapped
