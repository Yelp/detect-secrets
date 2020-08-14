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
