import mock
import pytest

from detect_secrets.plugins.common.yaml_file_parser import YamlFileParser
from testing.mocks import mock_file_object


class TestYamlFileParser:

    def test_get_ignored_lines(self):
        content = """keyA: value
        keyB: \"another_value\"  # pragma: allowlist secret
        keyC: \"another_value\"  # pragma: whitelist secret (backwards compatibility test)
        keyD: yet_another_value
        """

        f = mock_file_object(content)

        ignored_lines = YamlFileParser(f).get_ignored_lines()

        assert ignored_lines == {2, 3}

    @pytest.mark.parametrize(
        ['yaml_value', 'expected_value', 'expected_is_binary'],
        [
            ('string_value', 'string_value', False),
            ('!!binary YWJjZGVm', b'abcdef', True),
        ],
    )
    def test_possible_secret_format(
        self,
        yaml_value,
        expected_value,
        expected_is_binary,
    ):
        content = 'key: {yaml_value}'.format(yaml_value=yaml_value)
        f = mock_file_object(content)

        result = YamlFileParser(f).json()
        assert result['key'] == {
            '__value__': expected_value,
            '__is_binary__': expected_is_binary,
            '__line__': mock.ANY,
            '__original_key__': mock.ANY,
        }
