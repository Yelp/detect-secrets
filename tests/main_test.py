import json
from contextlib import contextmanager

import mock
import pytest

from detect_secrets.main import main
from testing.factories import secrets_collection_factory
from testing.mocks import Any
from testing.mocks import mock_open


@pytest.fixture
def mock_baseline_initialize():
    secrets = secrets_collection_factory()

    with mock.patch(
        'detect_secrets.main.baseline.initialize',
        return_value=secrets,
    ) as mock_initialize:
        yield mock_initialize


@pytest.fixture
def mock_merge_baseline():
    with mock.patch(
        'detect_secrets.main.baseline.merge_baseline',
    ) as m:
        # This return value doesn't matter, because we're not testing
        # for it. It just needs to be a dictionary, so it can be properly
        # JSON dumped.
        m.return_value = {}
        yield m


class TestMain(object):
    """These are smoke tests for the console usage of detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def test_smoke(self):
        with mock_stdin():
            assert main([]) == 0

    def test_scan_basic(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['--scan']) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            '.',
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        with mock_stdin():
            assert main('--scan test_data'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            'test_data',
        )

    def test_scan_with_excludes_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert main('--scan --exclude some_pattern_here'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            'some_pattern_here',
            '.',
        )

    def test_reads_from_stdin(self, mock_merge_baseline):
        with mock_stdin(json.dumps({'key': 'value'})):
            assert main(['--scan']) == 0

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )

    def test_reads_old_baseline_from_file(self, mock_merge_baseline):
        with mock_stdin(), mock_open(
            json.dumps({'key': 'value'}),
            'detect_secrets.main.open',
        ) as m:
            assert main('--scan --import old_baseline_file'.split()) == 0
            assert m.call_args[0][0] == 'old_baseline_file'

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )


@contextmanager
def mock_stdin(response=None):
    if not response:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = True
            yield

    else:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = False
            m.stdin.read.return_value = response
            yield
