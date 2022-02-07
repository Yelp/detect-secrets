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
            'keyC: "YWJjZGVm"',
            'keyD: "YWJjZGVm"     # with comments',
            'keyE: "invalidBinar"',
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

    @staticmethod
    def test_single_line_flow_mapping():
        file = mock_file_object(
            textwrap.dedent("""
            object:
                keyA: 1
                dictionary:
                    - {keyB: valueB, keyC: valueC, keyD: valueD}
            """)[1:-1],
        )

        assert YAMLTransformer().parse_file(file) == [
            '',
            '',
            '',
            'keyB: "valueB"',
            'keyC: "valueC"',
            'keyD: "valueD"',
        ]

    @staticmethod
    def test_multi_line_flow_mapping():
        file = mock_file_object(
            textwrap.dedent("""
            object:
                keyA: 1
                dictionary:
                    - {keyB: valueB, keyC: valueC, keyD: valueD}

            """)[1:-1],
        )

        assert YAMLTransformer().parse_file(file) == [
            '',
            '',
            '',
            'keyB: "valueB"',
            'keyC: "valueC"',
            'keyD: "valueD"',
        ]


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

    @staticmethod
    @pytest.mark.parametrize(
        'content, expected',
        (
            # NOTE: The trailing new lines are important here!
            # It needs to be a string value, since we ignore non-string values (because we assume
            # secrets will be strings). However, the combination of the dictionary start character
            # `{` and the keys being on the same line causes unexpected results (see #374).
            (
                textwrap.dedent("""
                    { a: "1" }
                """)[1:],
                ['a: "1"'],
            ),
            (
                textwrap.dedent("""
                    a:
                        {b: "2"}
                """)[1:],
                ['', 'b: "2"'],
            ),
            (
                textwrap.dedent("""
                    a:
                    - {b: "2"}
                """)[1:],
                ['', 'b: "2"'],
            ),
            # New lines aren't important here, but since the first key is on the same line
            # as the start of the block, it will be handled funkily.
            (
                textwrap.dedent("""
                    {a: "1",
                        b: "2",
                    }
                """)[1:-1],
                ['a: "1"', 'b: "2"'],
            ),
            (
                textwrap.dedent("""
                    {
                        a: "1",
                        b: "2",
                    }
                """)[1:],
                ['', 'a: "1"', 'b: "2"'],
            ),
            (
                textwrap.dedent("""
                    { a: "1", b: "2" }
                """)[1:],
                ['a: "1"', 'b: "2"'],
            ),
        ),
    )
    def test_inline_dictionary(content, expected):
        lines = YAMLTransformer().parse_file(mock_file_object(content))
        assert lines == expected

    @staticmethod
    def test_single_line_flow_mapping():
        file = mock_file_object(
            textwrap.dedent("""
            dictionary:
                - {keyA: valueA, keyB: valueB, keyC: valueC}
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'dictionary': [
                {
                    'keyA': {
                        '__value__': 'valueA',
                        '__line__': 2,
                        '__original_key__': 'keyA',
                    },
                    'keyB': {
                        '__value__': 'valueB',
                        '__line__': 2,
                        '__original_key__': 'keyB',
                    },
                    'keyC': {
                        '__value__': 'valueC',
                        '__line__': 2,
                        '__original_key__': 'keyC',
                    },
                },
            ],
        }

    @staticmethod
    def test_multi_line_flow_mapping():
        file = mock_file_object(
            textwrap.dedent("""
            dictionary:
                - {keyA: valueA, keyB: valueB, keyC: valueC}

            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'dictionary': [
                {
                    'keyA': {
                        '__value__': 'valueA',
                        '__line__': 2,
                        '__original_key__': 'keyA',
                    },
                    'keyB': {
                        '__value__': 'valueB',
                        '__line__': 2,
                        '__original_key__': 'keyB',
                    },
                    'keyC': {
                        '__value__': 'valueC',
                        '__line__': 2,
                        '__original_key__': 'keyC',
                    },
                },
            ],
        }

    @staticmethod
    def test_inline_dictionary_same_starting_line():
        file = mock_file_object(
            textwrap.dedent("""
                {a: "1",
                    b: "2",
                }
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'a': {
                '__value__': '1',
                '__line__': 1,
                '__original_key__': 'a',
            },
            'b': {
                '__value__': '2',
                '__line__': 2,
                '__original_key__': 'b',
            },
        }

    @staticmethod
    def test_inline_dictionary_different_starting_line():
        file = mock_file_object(
            textwrap.dedent("""
                {
                    a: "1",
                    b: "2",
                }
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'a': {
                '__value__': '1',
                '__line__': 2,
                '__original_key__': 'a',
            },
            'b': {
                '__value__': '2',
                '__line__': 3,
                '__original_key__': 'b',
            },
        }

    @staticmethod
    def test_inline_empty_mapping_line_numbers():
        file = mock_file_object(
            textwrap.dedent("""
                a: {}
                b: "2"
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'a': {},
            'b': {
                '__value__': '2',
                '__line__': 2,
                '__original_key__': 'b',
            },
        }

    @staticmethod
    def test_inline_mapping_single_line_single_key_line_numbers():
        file = mock_file_object(
            textwrap.dedent("""
                a: {b: "2"}
                c: "3"
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'a': {
                'b': {
                    '__value__': '2',
                    '__line__': 1,
                    '__original_key__': 'b',
                },
            },
            'c': {
                '__value__': '3',
                '__line__': 2,
                '__original_key__': 'c',
            },
        }

    @staticmethod
    def test_inline_mapping_single_line_multikey_line_numbers():
        file = mock_file_object(
            textwrap.dedent("""
                a: {b: "2", c: "3"}
                d: "4"
            """)[1:-1],
        )

        assert YAMLFileParser(file).json() == {
            'a': {
                'b': {
                    '__value__': '2',
                    '__line__': 1,
                    '__original_key__': 'b',
                },
                'c': {
                    '__value__': '3',
                    '__line__': 1,
                    '__original_key__': 'c',
                },
            },
            'd': {
                '__value__': '4',
                '__line__': 2,
                '__original_key__': 'd',
            },
        }
