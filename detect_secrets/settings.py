import json
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import List


@lru_cache(maxsize=1)
def get_settings() -> 'Settings':
    """
    This is essentially a singleton pattern, that allows for (controlled) global access
    to common variables.
    """
    return Settings()


def configure_settings_from_baseline(filename: str) -> 'Settings':
    """
    :raises: FileNotFoundError
    :raises: json.decoder.JSONDecodeError
    :raises: KeyError
    """
    with open(filename) as f:
        baseline = json.loads(f.read())

    get_settings().configure_plugins(baseline['plugins_used'])
    return get_settings()


class Settings:
    def __init__(self) -> None:
        # mapping of class names to initialization variables
        self.plugins: Dict[str, Dict[str, Any]] = {}

        # mapping of python import paths to configuration variables
        self.filters: Dict[str, Dict[str, Any]] = {}

    def configure_plugins(self, config: List[Dict[str, Any]]) -> 'Settings':
        """
        :param config: e.g.
            [
                {'name': 'AWSKeyDetector'},
                {'base64_limit': 4.5, 'name': 'Base64HighEntropyString'}
            ]
        """
        for plugin in config:
            # TODO: Can we remove this, once we fix up SecretsCollection?
            plugin = {**plugin}
            name = plugin.pop('name')
            self.plugins[name] = plugin

        return self

    def disable_plugins(self, *plugin_names: str) -> 'Settings':
        for name in plugin_names:
            try:
                self.plugins.pop(name)
            except KeyError:
                pass

        return self

    def configure_filters(self, config: List[Dict[str, Any]]) -> 'Settings':
        """
        :param config: e.g.
            [
                {'path': 'detect_secrets.filters.heuristic.is_sequential_string'},
                {
                    'path': 'detect_secrets.filters.regex.should_exclude_files',
                    'pattern': '^test.*',
                }
            ]
        """
        for filter_config in config:
            path = filter_config.pop('path')
            self.filters[path] = filter_config

        return self

    def json(self) -> Dict[str, Any]:
        return {
            'plugins_used': [
                {
                    'name': name,
                    **config,
                }
                for name, config in self.plugins.items()
            ],
            'filters_used': [
                {
                    'path': path,
                    **config,
                }
                for path, config in self.filters.items()
            ],
        }
