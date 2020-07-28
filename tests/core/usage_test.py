import pytest

from detect_secrets.plugins.common.util import import_plugins
from testing.util import parse_pre_commit_args_with_correct_prog


class TestPluginOptions:

    def test_added_by_default(self):
        # This is what happens with unrecognized arguments
        with pytest.raises(SystemExit):
            parse_pre_commit_args_with_correct_prog('--unrecognized-argument')

        parse_pre_commit_args_with_correct_prog('--no-private-key-scan')

    def test_consolidates_output_basic(self):
        """Everything enabled by default, with default values"""
        args = parse_pre_commit_args_with_correct_prog()

        regex_based_plugins = {
            key: {}
            for key in import_plugins(custom_plugin_paths=())
        }
        regex_based_plugins.update({
            'HexHighEntropyString': {
                'hex_limit': 3,
            },
            'Base64HighEntropyString': {
                'base64_limit': 4.5,
            },
            'KeywordDetector': {
                'keyword_exclude': None,
            },
        })
        assert not hasattr(args, 'no_private_key_scan')

    def test_consolidates_removes_disabled_plugins(self):
        args = parse_pre_commit_args_with_correct_prog('--no-private-key-scan')

        assert 'PrivateKeyDetector' not in args.plugins

    def test_help(self):
        with pytest.raises(SystemExit):
            parse_pre_commit_args_with_correct_prog('--help')

    @pytest.mark.parametrize(
        'argument_string,expected_value',
        [
            ('--hex-limit 5', 5.0),
            ('--hex-limit 2.3', 2.3),
            ('--hex-limit 0', 0),
            ('--hex-limit 8', 8),
            ('--hex-limit -1', None),
            ('--hex-limit 8.1', None),
        ],
    )
    def test_custom_limit(self, argument_string, expected_value):
        if expected_value is not None:
            args = parse_pre_commit_args_with_correct_prog(argument_string)

            assert (
                args.plugins['HexHighEntropyString']['hex_limit']
                == expected_value
            )
        else:
            with pytest.raises(SystemExit):
                parse_pre_commit_args_with_correct_prog(argument_string)

    @pytest.mark.parametrize(
        'argument_string,expected_value',
        [
            ('--custom-plugins testing', ('testing',)),
            ('--custom-plugins does_not_exist', None),
        ],
    )
    def test_custom_plugins(self, argument_string, expected_value):
        if expected_value is not None:
            args = parse_pre_commit_args_with_correct_prog(argument_string)

            assert (
                args.custom_plugin_paths
                == expected_value
            )
        else:
            with pytest.raises(SystemExit):
                parse_pre_commit_args_with_correct_prog(argument_string)
