import os
import importlib
import pkgutil
import inspect
from abc import ABC
from git import Repo, InvalidGitRepositoryError

from detect_secrets import plugins as ds_plugins
from detect_secrets.plugins.base import BasePlugin


def is_concrete_class(cls):
    return (
        not inspect.isabstract(cls)
        and issubclass(cls, BasePlugin)
        and cls is not BasePlugin
    )


def load_all_plugins():
    """
    Load and return all available plugins from detect-secrets.
    """
    plugins = []
    package = ds_plugins
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_name}")
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if is_concrete_class(obj):
                plugins.append(obj())
    return plugins


def load_plugin_by_name(plugin_name: str):
    """
    Dynamically load and return an instance of the specified plugin by name.
    """
    package = ds_plugins
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_name}")
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if name == plugin_name and is_concrete_class(obj):
                return obj()
    raise ValueError(
        f"Error: no plugin found with name: '{plugin_name}'. To get the list of supported plugins, call list_plugins()"
    )


def load_specified_plugins(plugin_names: [str]):
    """
    Dynamically load and return specified plugins by name.
    """
    plugins = []
    for plugin_name in plugin_names:
        plugins.append(load_plugin_by_name(plugin_name))
    return plugins


def list_plugins():
    """
    Retunr a list of available plugins to use.
    """
    plugins = []
    package = ds_plugins
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_name}")
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if is_concrete_class(obj):
                plugins.append(name)
    return plugins


def scan_string(string_to_check: str, plugins: str = "all"):
    """
    Scan a string for secrets using the specified plugins.

    Args:
    string_to_check (str): string to to scan for secrets.
    plugins (str): Names of the comma (,) separated detect-secrets plugin names to use.
    """
    if not isinstance(string_to_check, str):
        raise ValueError(f"Error: '{string_to_check}' must be 'string' object")

    if not isinstance(plugins, str):
        raise ValueError(
            f"Error: '{plugins}' must be comma (,) sepated 'string' object"
        )

    if plugins == "all":
        detectors = load_all_plugins()
    else:
        plugin_names = plugins.split(",")
        detectors = load_specified_plugins(plugin_names)

    found_secrets = {}
    for detector in detectors:
        secrets = detector.analyze_string(string_to_check)
        detector_name = detector.json().get("name")
        for secret in secrets:
            if detector_name not in found_secrets:
                found_secrets[detector_name] = [secret]
            elif secret not in found_secrets[detector_name]:
                found_secrets[detector_name].append(secret)
    return found_secrets


def scan_file(filepath: str, plugins: str = "all"):
    """
    Scan a local file for secrets using the specified plugins.

    Args:
    filepath (str): Path to the local file.
    plugins (str): Names of the comma (,) separated detect-secrets plugin names to use.
    """
    if not isinstance(filepath, str):
        raise ValueError(
            f"Error: '{filepath}' must be 'string' formatted path to a file"
        )

    try:
        with open(filepath, "r") as file:
            lines = file.readlines()
        found_secrets = {}
        for idx, line in enumerate(lines):
            secrets_in_line = scan_string(line, plugins)
            if secrets_in_line != {}:
                found_secrets[f"Line {idx + 1}"] = secrets_in_line
        return found_secrets
    except Exception as e:
        raise ValueError(f"Error scanning '{filepath}': {e}")


def scan_git_repository(
    repo_path: str, plugins: str = "all", scan_all_files: bool = False
):
    """
    Scan a local Git repository for secrets using the specified plugins.

    Args:
    repo_path (str): Path to the local Git repository.
    plugins (str): Names of the comma (,) separated detect-secrets plugin names to use.
    scan_all_files (bool): If True, scan all files in the repository. If False, scan only Git-tracked files.
    """
    if not isinstance(scan_all_files, bool):
        raise ValueError(f"Error: 'scan_all_files' must be 'bool' type")

    try:
        repo = Repo(repo_path)
        if repo.bare:
            raise InvalidGitRepositoryError

        files_to_scan = []
        if scan_all_files:
            for root, _, files in os.walk(repo_path):
                if ".git" in root:
                    continue
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
        else:
            files_to_scan = [
                os.path.join(repo_path, item.a_path) for item in repo.index.diff(None)
            ]
            files_to_scan.extend(
                [os.path.join(repo_path, item) for item in repo.untracked_files]
            )

        found_secrets = {}
        for filepath in files_to_scan:
            secrets_in_file = scan_file(filepath, plugins)
            if secrets_in_file != {}:
                found_secrets[filepath] = secrets_in_file
        return found_secrets
    except InvalidGitRepositoryError:
        raise ValueError(f"Error: '{repo_path}' is not a valid Git repositoty")
