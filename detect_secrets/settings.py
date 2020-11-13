from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import Generator
from typing import List


@lru_cache(maxsize=1)
def get_settings() -> 'Settings':
    """
    This is essentially a singleton pattern, that allows for (controlled) global access
    to common variables.
    """
    return Settings()


def configure_settings_from_baseline(baseline: Dict[str, Any], filename: str = '') -> 'Settings':
    """
    :raises: KeyError
    """
    settings = get_settings()

    if 'plugins_used' in baseline:
        settings.configure_plugins(baseline['plugins_used'])

    if 'filters_used' in baseline:
        settings.configure_filters(baseline['filters_used'])

    if filename:
        settings.filters['detect_secrets.filters.common.is_baseline_file'] = {
            'filename': filename,
        }

    return settings


@contextmanager
def transient_settings(config: Dict[str, Any]) -> Generator['Settings', None, None]:
    """Allows the customizability of non-global settings per invocation."""
    original_settings = get_settings().json()

    cache_bust()
    try:
        yield configure_settings_from_baseline(config)
    finally:
        cache_bust()
        configure_settings_from_baseline(original_settings)


def cache_bust() -> None:
    from detect_secrets.core.scan import get_filters
    from detect_secrets.core.scan import get_plugins

    get_settings.cache_clear()
    get_filters.cache_clear()
    get_plugins.cache_clear()


class Settings:
    DEFAULT_FILTERS = {
        'detect_secrets.filters.common.is_invalid_file',
        'detect_secrets.filters.heuristic.is_non_text_file',
    }

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        # mapping of class names to initialization variables
        self.plugins: Dict[str, Dict[str, Any]] = {}

        # mapping of python import paths to configuration variables
        self.filters: Dict[str, Dict[str, Any]] = {
            path: {}
            for path in {
                *self.DEFAULT_FILTERS,
                'detect_secrets.filters.allowlist.is_line_allowlisted',
                'detect_secrets.filters.heuristic.is_sequential_string',
                'detect_secrets.filters.heuristic.is_potential_uuid',
                'detect_secrets.filters.heuristic.is_likely_id_string',
            }
        }

    def configure_plugins(self, config: List[Dict[str, Any]]) -> 'Settings':
        """
        :param config: e.g.
            [
                {'name': 'AWSKeyDetector'},
                {'limit': 4.5, 'name': 'Base64HighEntropyString'}
            ]
        """
        for plugin in config:
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
        self.filters = {
            path: {}
            for path in self.DEFAULT_FILTERS
        }

        # Make a copy, so we don't affect the original.
        filter_configs = deepcopy(config)
        for filter_config in filter_configs:
            path = filter_config.pop('path')
            self.filters[path] = filter_config

        return self

    def disable_filters(self, *filter_paths: str) -> 'Settings':
        new_filters = {}
        for filter_path, config in self.filters.items():
            if filter_path not in filter_paths:
                new_filters[filter_path] = config

        self.filters = new_filters
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
                if path not in self.DEFAULT_FILTERS
            ],
        }
