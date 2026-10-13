import pytest

from detect_secrets.util.code_snippet import get_code_snippet


@pytest.mark.parametrize(
    'line_number, expected',
    (
        (1, 'abc'),
        (3, 'abcde'),
        (4, 'bcde'),
        (5, 'cde'),
    ),
)
def test_basic(line_number, expected):
    assert ''.join(
        list(get_code_snippet(list('abcde'), line_number, lines_of_context=2)),
    ) == expected


def test_target_line():
    assert get_code_snippet(list('abcde'), 3, lines_of_context=2).target_line == 'c'


def test_previous_line():
    assert get_code_snippet(list('abcde'), 3, lines_of_context=2).previous_line == 'b'


def test_truncate_long_context_lines():
    snippet = get_code_snippet(
        ['prefix' * 50, 'target = "secret"', 'suffix' * 50],
        2,
        lines_of_context=1,
    )
    snippet.truncate_lines(40, 'secret')
    assert snippet.target_line == 'target = "secret"'
    assert len(snippet.lines[0]) <= 40
    assert len(snippet.lines[2]) <= 40


@pytest.mark.parametrize('prefix_length', (0, 60, 180))
def test_truncate_target_preserves_highlighted_secret(prefix_length):
    secret = 'SYNTHETICSECRET12'
    target = ('x' * prefix_length) + secret + ('y' * 170)
    snippet = get_code_snippet([target], 1)
    snippet.truncate_lines(60, secret)
    assert secret in snippet.target_line
    assert len(snippet.target_line) <= 60
    snippet.highlight_line(secret)


def test_truncate_longer_than_budget_secret_is_not_lost():
    secret = 'S' * 90
    snippet = get_code_snippet(['left-' + secret + '-right'], 1)
    snippet.truncate_lines(50, secret)
    assert secret in snippet.target_line
    snippet.highlight_line(secret)


def test_truncate_invalid_width():
    snippet = get_code_snippet(['anything'], 1)
    with pytest.raises(ValueError):
        snippet.truncate_lines(12)
