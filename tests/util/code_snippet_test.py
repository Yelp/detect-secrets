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
