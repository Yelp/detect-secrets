import pytest

from detect_secrets.filters.allowlist import is_line_allowlisted


@pytest.mark.parametrize(
    'prefix, suffix',
    (
        ('#', ''),
        ('# ', ' more text'),

        ('//', ''),
        ('// ', ' more text'),

        ('/*', '*/'),
        ('/* ', ' */'),

        ('--', ''),
        ('-- ', ' more text'),

        ('<!--', '-->'),
    ),
)
def test_basic(prefix, suffix):
    assert is_line_allowlisted(
        'filename',
        f'AKIAEXAMPLE  {prefix}pragma: allowlist secret{suffix}',
    )


@pytest.mark.parametrize(
    'line, expected_result',
    (
        ('key: value # pragma: allowlist secret', True),
        ('key: value // pragma: allowlist secret', False),
    ),
)
def test_file_based_regexes(line, expected_result):
    assert is_line_allowlisted('filename.yaml', line) is expected_result
