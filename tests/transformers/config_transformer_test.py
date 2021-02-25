import configparser
import textwrap

import pytest

from detect_secrets.transformers.config import ConfigFileTransformer
from detect_secrets.transformers.config import EagerConfigFileTransformer
from detect_secrets.transformers.config import IniFileParser
from testing.mocks import mock_file_object


@pytest.mark.parametrize(
    'transformer',
    (
        ConfigFileTransformer,
        EagerConfigFileTransformer,
    ),
)
def test_transformer(transformer):
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            keyA = value

            keyB = "double"
            keyC = 'single'

            keyD = o'brian
            keyE = "chai" tea
        """)[1:-1],
    )

    assert transformer().parse_file(file) == [
        '',
        'keyA = "value"',
        '',
        'keyB = "double"',
        'keyC = "single"',
        '',
        'keyD = "o\'brian"',
        'keyE = "\\\"chai\\\" tea"',
    ]


def test_basic():
    file = mock_file_object(
        textwrap.dedent("""
            [section]
            key = value
            rice = fried

            # comment
            tea = chai

            [other]

            water = unflavored
        """)[1:-1],
    )

    assert list(IniFileParser(file)) == [
        ('key', 'value', 2),
        ('rice', 'fried', 3),
        ('tea', 'chai', 6),
        ('water', 'unflavored', 10),
    ]


@pytest.mark.parametrize(
    'content',
    (
        textwrap.dedent("""
            key = value

            # comment
            tea = chai
        """)[1:-1],

        # This case needs `add_header=True` to work.
        textwrap.dedent("""
            key = value

            [other]
            water = unflavored
        """)[1:-1],
    ),
)
def test_not_ini_file(content):
    file = mock_file_object(content)

    with pytest.raises(configparser.Error):
        list(IniFileParser(file))


def test_add_header():
    file = mock_file_object(
        textwrap.dedent("""
            key = value

            # comment
            tea = chai
        """)[1:-1],
    )

    assert list(IniFileParser(file, add_header=True)) == [
        ('key', 'value', 1),
        ('tea', 'chai', 4),
    ]


class TestMultipleValues:
    @staticmethod
    def test_all():
        file = mock_file_object(
            textwrap.dedent("""
                [section]
                key = value0
                    value1

                    # comment
                    value2
            """)[1:-1],
        )

        assert list(IniFileParser(file)) == [
            ('key', 'value0', 2),
            ('key', 'value1', 3),
            ('key', 'value2', 6),
        ]

    @staticmethod
    def test_not_first():
        file = mock_file_object(
            textwrap.dedent("""
                [section]
                key =
                    value1

                    # comment
                    value2
            """)[1:-1],
        )

        assert list(IniFileParser(file)) == [
            ('key', 'value1', 3),
            ('key', 'value2', 6),
        ]
