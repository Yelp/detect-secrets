import argparse
import os

from ...settings import get_settings
from ..plugins.util import get_mapping_from_secret_type_to_class


def valid_path(path: str) -> str:
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(
            f'Invalid path: {path}',
        )

    return path


def initialize_plugin_settings(args: argparse.Namespace) -> None:
    """
    This is a stand-in function, which should be replaced if baseline options are used.
    This ensures that our global settings object is initialized to a minimal state
    (all built-in plugins, default options)
    """
    # TODO: This should take cli args (e.g. --base64-limit)
    get_settings().configure_plugins([
        {'name': plugin_type.__name__}
        for plugin_type in get_mapping_from_secret_type_to_class().values()
    ])
