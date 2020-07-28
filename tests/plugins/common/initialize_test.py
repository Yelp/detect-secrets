import mock
import pytest

from detect_secrets.plugins.common import initialize
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString


class TestFromPluginClassname:

    def test_success(self):
        plugin = initialize.from_plugin_classname(
            plugin_classname='HexHighEntropyString',
            custom_plugin_paths=(),
            hex_limit=4,
        )

        # Dynamically imported classes have different
        # addresses for the same functions as statically
        # imported classes do, so isinstance does not work.
        assert str(plugin.__class__) == str(HexHighEntropyString)
        assert dir(plugin.__class__) == dir(HexHighEntropyString)

        assert plugin.entropy_limit == 4

    def test_fails_if_not_base_plugin(self):
        with pytest.raises(TypeError):
            initialize.from_plugin_classname(
                plugin_classname='NotABasePlugin',
                custom_plugin_paths=(),
            )

    def test_fails_on_bad_initialization(self):
        with mock.patch(
            'detect_secrets.plugins.common.initialize.import_plugins',
            # Trying to instantiate str() like a plugin throws TypeError
            return_value={'HexHighEntropyString': str},
        ), pytest.raises(
            TypeError,
        ):
            initialize.from_plugin_classname(
                plugin_classname='HexHighEntropyString',
                custom_plugin_paths=(),
                hex_limit=4,
            )


class TestFromSecretType:

    def setup(self):
        self.plugins_used = [
            {
                'name': 'Base64HighEntropyString',
                'base64_limit': 3,
            },
            {
                'name': 'PrivateKeyDetector',
            },
        ]

    def test_success(self):
        plugin = initialize.from_secret_type(
            'Base64 High Entropy String',
            plugins_used=self.plugins_used,
            custom_plugin_paths=(),
        )
        # Dynamically imported classes have different
        # addresses for the same functions as statically
        # imported classes do, so isinstance does not work.
        assert str(plugin.__class__) == str(Base64HighEntropyString)
        assert dir(plugin.__class__) == dir(Base64HighEntropyString)

        assert plugin.entropy_limit == 3

    def test_failure(self):
        assert not initialize.from_secret_type(
            'some random secret_type',
            plugins_used=self.plugins_used,
            custom_plugin_paths=(),
        )

    def test_secret_type_not_in_settings(self):
        assert not initialize.from_secret_type(
            'Base64 High Entropy String',
            plugins_used=[],
            custom_plugin_paths=(),
        )
