import pytest

from detect_secrets import filters
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import default_settings
from detect_secrets.settings import get_settings


@pytest.fixture
def parser():
    # NOTE: We perform the testing via ParserBuilder since that is responsible for initializing
    # the settings as expected. We use `add_pre_commit_arguments` so that we don't need to prefix
    # the arguments with `scan`.
    return ParserBuilder().add_pre_commit_arguments()


def test_should_exclude_line(parser):
    parser.parse_args([
        '--exclude-lines', 'canarytoken',
        '--exclude-lines', '^not-real-secret = .*$',
    ])
    assert filters.regex.should_exclude_line('password = "canarytoken"') is True
    assert filters.regex.should_exclude_line('password = "hunter2"') is False
    assert filters.regex.should_exclude_line('not-real-secret = value') is True
    assert filters.regex.should_exclude_line('maybe-not-real-secret = value') is False

    assert [
        item
        for item in get_settings().json()['filters_used']
        if item['path'] == 'detect_secrets.filters.regex.should_exclude_line'
    ] == [
        {
            'path': 'detect_secrets.filters.regex.should_exclude_line',
            'pattern': [
                'canarytoken',
                '^not-real-secret = .*$',
            ],
        },
    ]


def test_should_exclude_file(parser):
    parser.parse_args([
        '--exclude-files', '^tests/.*',
        '--exclude-files', '.*/i18/.*',
    ])
    assert filters.regex.should_exclude_file('tests/blah.py') is True
    assert filters.regex.should_exclude_file('detect_secrets/tests/blah.py') is False
    assert filters.regex.should_exclude_file('app/messages/i18/en.properties') is True
    assert filters.regex.should_exclude_file('app/i18secrets/secrets.yaml') is False

    assert [
        item
        for item in get_settings().json()['filters_used']
        if item['path'] == 'detect_secrets.filters.regex.should_exclude_file'
    ] == [
        {
            'path': 'detect_secrets.filters.regex.should_exclude_file',
            'pattern': [
                '^tests/.*',
                '.*/i18/.*',
            ],
        },
    ]


def test_should_exclude_secret(parser):
    parser.parse_args([
        '--exclude-secrets', '^[Pp]assword[0-9]{0,3}$',
        '--exclude-secrets', 'my-first-password',
    ])
    assert filters.regex.should_exclude_secret('Password123') is True
    assert filters.regex.should_exclude_secret('MyRealPassword') is False
    assert filters.regex.should_exclude_secret('1-my-first-password-for-database') is True
    assert filters.regex.should_exclude_secret('my-password') is False

    assert [
        item
        for item in get_settings().json()['filters_used']
        if item['path'] == 'detect_secrets.filters.regex.should_exclude_secret'
    ] == [
        {
            'path': 'detect_secrets.filters.regex.should_exclude_secret',
            'pattern': [
                '^[Pp]assword[0-9]{0,3}$',
                'my-first-password',
            ],
        },
    ]


def test_cache_should_be_cleared_with_different_settings(parser):
    with default_settings():
        parser.parse_args([
            '--exclude-lines', 'abcde',
        ])

        assert filters.regex.should_exclude_line('abcde') is True

    # Since the regex isn't cached anymore, it needs to be regenerated. However,
    # we didn't configure the regex in the settings object, so it will raise a KeyError
    # when trying to obtain the patterns.
    with pytest.raises(KeyError):
        assert filters.regex.should_exclude_line('abcde')
