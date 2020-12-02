import pytest

from detect_secrets.core.plugins import initialize
from detect_secrets.exceptions import InvalidFile
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.settings import get_settings


@pytest.fixture(autouse=True)
def setup_settings():
    get_settings().configure_plugins([
        {
            'name': 'Base64HighEntropyString',
            'limit': 3,
        },
        {
            'name': 'PrivateKeyDetector',
        },
    ])


class TestFromSecretType:
    @staticmethod
    @pytest.mark.parametrize(
        'plugin_type',
        (
            Base64HighEntropyString,
            PrivateKeyDetector,
        ),
    )
    def test_success(plugin_type):
        plugin = initialize.from_secret_type(plugin_type.secret_type)

        assert isinstance(plugin, plugin_type)
        if plugin_type == Base64HighEntropyString:
            assert plugin.entropy_limit == 3

    @staticmethod
    def test_failure():
        with pytest.raises(TypeError):
            initialize.from_secret_type('does not exist')

    @staticmethod
    def test_secret_type_not_in_settings():
        with pytest.raises(TypeError):
            initialize.from_secret_type('does not exist')


class TestFromPluginClassName:
    @staticmethod
    @pytest.mark.parametrize(
        'plugin_type',
        (
            Base64HighEntropyString,
            PrivateKeyDetector,
        ),
    )
    def test_success(plugin_type):
        plugin = initialize.from_plugin_classname(plugin_type.__name__)

        assert isinstance(plugin, plugin_type)
        if plugin_type == Base64HighEntropyString:
            assert plugin.entropy_limit == 3

    @staticmethod
    def test_no_such_plugin():
        with pytest.raises(TypeError):
            initialize.from_plugin_classname('NotAPlugin')


class TestFromFile:
    @staticmethod
    def test_success():
        plugins = initialize.from_file('testing/plugins.py')
        assert len(plugins) == 1
        assert plugins[0].secret_type == 'Hippo'
        assert initialize.from_secret_type('Hippo') == plugins[0]()

    @staticmethod
    def test_no_such_file():
        with pytest.raises(FileNotFoundError):
            initialize.from_file('does-not-exist')

    @staticmethod
    def test_non_python_file():
        with pytest.raises(InvalidFile):
            initialize.from_file('test_data/config.env')

    @staticmethod
    def test_no_compatible_plugins():
        assert not initialize.from_file('testing/mocks.py')
