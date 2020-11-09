import pytest

from detect_secrets import filters
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.settings import get_settings


@pytest.fixture
def parser():
    # NOTE: We perform the testing via ParserBuilder since that is responsible for initializing
    # the settings as expected. We use `add_pre_commit_arguments` so that we don't need to prefix
    # the arguments with `scan`.
    return ParserBuilder().add_pre_commit_arguments()


def test_should_exclude_line(parser):
    parser.parse_args(['--exclude-lines', 'canarytoken'])
    assert filters.regex.should_exclude_line('password = "canarytoken"') is True
    assert filters.regex.should_exclude_line('password = "hunter2"') is False

    assert [
        item
        for item in get_settings().json()['filters_used']
        if item['path'] == 'detect_secrets.filters.regex.should_exclude_line'
    ] == [
        {
            'path': 'detect_secrets.filters.regex.should_exclude_line',
            'pattern': 'canarytoken',
        },
    ]


def test_should_exclude_file(parser):
    parser.parse_args(['--exclude-files', '^tests/.*'])
    assert filters.regex.should_exclude_file('tests/blah.py') is True
    assert filters.regex.should_exclude_file('detect_secrets/tests/blah.py') is False

    assert [
        item
        for item in get_settings().json()['filters_used']
        if item['path'] == 'detect_secrets.filters.regex.should_exclude_file'
    ] == [
        {
            'path': 'detect_secrets.filters.regex.should_exclude_file',
            'pattern': '^tests/.*',
        },
    ]
