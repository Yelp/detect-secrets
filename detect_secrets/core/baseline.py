import json
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util.importlib import import_modules_from_package
from ..util.semver import Version
from .scan import get_files_to_scan
from .secrets_collection import SecretsCollection


def create(*paths: str, should_scan_all_files: bool = False) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    secrets = SecretsCollection()

    for filename in get_files_to_scan(*paths, should_scan_all_files=should_scan_all_files):
        secrets.scan_file(filename)

    return secrets


def load(baseline: Dict[str, Any], filename: str = '') -> SecretsCollection:
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
            return cast(Dict[str, Any], json.loads(f.read()))
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise UnableToReadBaselineError from e


def format_for_output(secrets: SecretsCollection, is_slim_mode: bool = False) -> Dict[str, Any]:
    output = {
        'version': VERSION,

        # This will populate settings of filters and plugins,
        **get_settings().json(),

        'results': secrets.json(),
    }

    if not is_slim_mode:
        output['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    else:
        # NOTE: This has a nice little side effect of keeping it ordered by line number,
        # even though we don't output it.
        for filename, secrets in output['results'].items():
            for secret_dict in secrets:
                secret_dict.pop('line_number')

    return output


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
        module.upgrade(new_baseline)    # type: ignore

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
