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


class Settings:
    def __init__(self) -> None:
        self.plugins: Dict[str, Any] = {}

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
