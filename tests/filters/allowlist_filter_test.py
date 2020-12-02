import pytest

from detect_secrets.filters.allowlist import is_line_allowlisted
from detect_secrets.util.code_snippet import CodeSnippet


EXAMPLE_COMMENT_PARTS = (
    ('#', ''),
    ('# ', ' more text'),

    ('//', ''),
    ('// ', ' more text'),

    ('/*', '*/'),
    ('/* ', ' */'),

    ('--', ''),
    ('-- ', ' more text'),

    ('<!--', '-->'),
)


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_basic(prefix, suffix):
    line = f'AKIAEXAMPLE  {prefix}pragma: allowlist secret{suffix}'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'prefix, suffix',
    EXAMPLE_COMMENT_PARTS,
)
def test_nextline(prefix, suffix):
    comment = f'{prefix}pragma: allowlist nextline secret{suffix}'
    line = 'AKIAEXAMPLE'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([comment, line], 0, 1),
    )


def test_nextline_exclusivity():
    line = 'AKIAEXAMPLE  # pragma: allowlist nextline secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    ) is False


def test_backwards_compatibility():
    line = 'AKIAEXAMPLE  # pragma: whitelist secret'
    assert is_line_allowlisted(
        'filename',
        line,
        CodeSnippet([line], 0, 0),
    )


@pytest.mark.parametrize(
    'line, expected_result',
    (
        ('key: value # pragma: allowlist secret', True),
        ('key: value // pragma: allowlist secret', False),
    ),
)
def test_file_based_regexes(line, expected_result):
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([line], 0, 0),
    ) is expected_result


@pytest.mark.parametrize(
    'comment, expected_result',
    (
        ('# pragma: allowlist nextline secret', True),
        ('// pragma: allowlist nextline secret', False),
    ),
)
def test_file_based_nextline_regexes(comment, expected_result):
    line = 'key: value'
    assert is_line_allowlisted(
        'filename.yaml',
        line,
        CodeSnippet([comment, line], 0, 1),
    ) is expected_result
