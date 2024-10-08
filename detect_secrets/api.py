import os
from typing import Dict
from typing import List

from git import Repo

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
from detect_secrets.settings import transient_settings


def get_settings(filters: list = None, plugins: list = None) -> Dict[str, List]:
    """
    Return used plugins and filters to be used to scan with provided params
    """
    if filters and not isinstance(filters, list):
        raise ValueError(f"Error: '{filters}' must be List object")

    if plugins and not isinstance(plugins, list):
        raise ValueError(f"Error: '{plugins}' must be List object")

    if filters:
        filters_used = filters
    else:
        filters_used = []
        with default_settings() as settings:
            for key in settings.filters:
                filters_used.append({'path': key})

    if plugins:
        plugins_used = plugins
    else:
        plugins_used = []
        with default_settings() as settings:
            for key in settings.plugins:
                plugins_used.append({'name': key})

    return {'plugins': plugins_used, 'filters': filters_used}


def scan_string(
    string: str, filters: list = None, plugins: list = None,
) -> Dict[str, List]:
    """
    Scan a string for secrets using detect-secrets with custom filters and plugins

    :param string: String to scan
    :param filters: Custom filters for detect-secrets
    :param plugins: Custom plugins for detect-secrets
    :return: Detected secrets in str format
    """
    if not isinstance(string, str):
        raise ValueError(f"Error: '{string}' must be 'string' object")

    if filters and not isinstance(filters, list):
        raise ValueError(f"Error: '{filters}' must be List object")

    if plugins and not isinstance(plugins, list):
        raise ValueError(f"Error: '{plugins}' must be List object")

    # Initialize a SecretsCollection
    secrets = SecretsCollection()

    # Load default settings if no filters and plugins provided:
    if not filters and not plugins:
        settings = default_settings()
        # Scan the string
        with settings:
            secrets.scan_string(string)
        return secrets.json()
    elif filters and not plugins:
        plugins = get_settings(plugins=plugins).get('plugins')
    elif not filters and plugins:
        filters = get_settings(filters=filters).get('filters')

    # Scan the string
    settings = transient_settings({'plugins_used': plugins, 'filters_used': filters})
    with settings:
        secrets.scan_string(string)
        return secrets.json()


def scan_file(
    filepath: str, filters: list = None, plugins: list = None,
) -> Dict[str, List]:
    """
    Scan a file for secrets using detect-secrets with custom filters and plugins

    :param filepath: Path to the file to scan
    :param filters: Custom filters for detect-secrets
    :param plugins: Custom plugins for detect-secrets
    :return: Detected secrets in str format
    """
    if not isinstance(filepath, str):
        raise ValueError(
            f"Error: '{filepath}' must be 'string' formatted path to a file",
        )

    if filters and not isinstance(filters, list):
        raise ValueError(f"Error: '{filters}' must be List object")

    if plugins and not isinstance(plugins, list):
        raise ValueError(f"Error: '{plugins}' must be List object")

    try:
        with open(filepath, 'r') as f:
            f.read()
    except Exception:
        raise ValueError(f"Error: Cannot read '{filepath}'")
    # Initialize a SecretsCollection
    secrets = SecretsCollection()

    # Load default settings if no filters and plugins provided:
    if not filters and not plugins:
        settings = default_settings()
        # Scan the file
        with settings:
            secrets.scan_file(filepath)
        return secrets.json()
    elif filters and not plugins:
        plugins = get_settings(plugins=plugins).get('plugins')
    elif not filters and plugins:
        filters = get_settings(filters=filters).get('filters')

    # Scan a file
    settings = transient_settings(
        {'plugins_used': plugins, 'filters_used': filters},
    )
    with settings:
        secrets.scan_file(filepath)
        return secrets.json()


def scan_git_repository(
    repo_path: str,
    plugins: list = None,
    filters: list = None,
    scan_all_files: bool = False,
) -> List[Dict]:
    """
    Scan a local Git repository for secrets using the specified plugins and filters

    Args:
    :param repo_path: Path to the local Git repository
    :param filters: Custom filters for detect-secrets
    :param plugins: Custom plugins for detect-secrets
    :param scan_all_files (bool): Scan all files or only Git-tracked files.
    :return: Detected secrets in List format
    """
    if not isinstance(scan_all_files, bool):
        raise ValueError(f"Error: '{scan_all_files}' must be 'bool' type")
    if not isinstance(repo_path, str):
        raise ValueError(f"Error: '{repo_path}' must be 'str' type path to repository")

    try:
        repo = Repo(repo_path)
        files_to_scan = []
        if scan_all_files:
            for root, _, files in os.walk(repo_path):
                if '.git' in root:
                    continue
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            files_to_scan = [
                os.path.join(repo_path, item.a_path) for item in repo.index.diff(None)
            ]
            files_to_scan.extend(
                [os.path.join(repo_path, item) for item in repo.untracked_files],
            )

        results = []
        for filepath in files_to_scan:
            secrets = scan_file(filepath, plugins=plugins, filters=filters)
            if secrets != {}:
                results.append(secrets)
        return results

    except Exception:
        raise ValueError(f"Error: '{repo_path}' is not a valid Git repository")
