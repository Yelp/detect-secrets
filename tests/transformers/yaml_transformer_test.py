import textwrap
from unittest import mock

import pytest

from detect_secrets.transformers.yaml import YAMLFileParser
from detect_secrets.transformers.yaml import YAMLTransformer
from testing.mocks import mock_file_object


class TestYAMLTransformer:
    @staticmethod
    def test_basic():
        file = mock_file_object(
            textwrap.dedent("""
                keyA: string
                keyB: string    # with comments

                keyC: !!binary YWJjZGVm
                keyD: !!binary YWJjZGVm     # with comments
                keyE: !!binary invalidBinar

                dict:
                    keyD: nested string

                num: 1  # don't care
            """)[1:-1],
        )

        assert YAMLTransformer().parse_file(file) == [
            'keyA: "string"',
            'keyB: "string"    # with comments',
            '',
            'keyC: "abcdef"',
            'keyD: "abcdef"     # with comments',
            '',
            '',
            '',
            'keyD: "nested string"',
        ]

    @staticmethod
    @pytest.mark.xfail(reason='TODO')
    @pytest.mark.parametrize(
        'block_chomping',
        ('', '-', '+'),
    )
    def test_multiline_block_scalar_folded_style(block_chomping):
        # NOTE(2020-11-07|domanchi): For YAML parsing, we don't really care about "literal" style
        # (the one with `|`) since that will keep new lines, and our assumption is that secrets
        # won't have new lines.
        #
        # However, "folded" style may be used to keep a certain line limit with very long secrets,
        # so we should probably handle that.
        file = mock_file_object(
            textwrap.dedent(f"""
                multiline: |{block_chomping}    # example
                    this is
                    a basic multiline string
            """)[1:-1],
        )

        assert YAMLTransformer().parse_file(file) == [
            'multiline: this is a basic multiline string    # example',
        ]

    @staticmethod
    @pytest.mark.xfail(reason='TODO')
    @pytest.mark.parametrize(
        'block_chomping',
        ('', '-', '+'),
    )
    def test_multiline_block_scalar_literal_style(block_chomping):
        file = mock_file_object(
            textwrap.dedent("""
                multiline: >
                    this will be skipped
            """)[1:-1],
        )

        assert YAMLTransformer().parse_file(file) == ['']


class TestYAMLFileParser:
    @staticmethod
    def test_basic():
        file = mock_file_object(
            textwrap.dedent("""
                keyA: string
                dict:
                    keyB: 123
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'keyA': {
                '__value__': 'string',
                '__line__': 1,
                '__original_key__': 'keyA',
            },

            # Ignores non-string or non-binary
            'dict': {
                'keyB': 123,
            },
        }

    @staticmethod
    @pytest.mark.parametrize(
        'block_scalar_style',
        ('>', '|'),
    )
    @pytest.mark.parametrize(
        'block_chomping',
        ('', '-', '+'),
    )
    def test_multi_line(block_scalar_style, block_chomping):
        # NOTE: Referenced https://yaml-multiline.info/ for the many ways to do multi line strings
        file = mock_file_object(
            textwrap.dedent(f"""
                key: {block_scalar_style}{block_chomping}   # comment
                    multi
                    #line
                    string
            """)[1:-1],
        )

        assert [item.line for item in YAMLFileParser(file)] == [
            f'key: {block_scalar_style}{block_chomping}   # comment',
        ]

    @staticmethod
    @pytest.mark.parametrize(
        ['yaml_value', 'expected_value'],
        [
            ('string_value', 'string_value'),
            ('!!binary YWJjZGVm', b'abcdef'),
        ],
    )
    def test_possible_secret_format(yaml_value, expected_value):
        content = 'key: {yaml_value}'.format(yaml_value=yaml_value)
        f = mock_file_object(content)

        result = YAMLFileParser(f).json()
        assert result['key'] == {
            '__value__': expected_value,
            '__line__': mock.ANY,
            '__original_key__': mock.ANY,
        }
