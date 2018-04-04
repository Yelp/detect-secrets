import mock
import pytest

from detect_secrets.main import main
from tests.util.factories import secrets_collection_factory
from tests.util.mock_util import Any


@pytest.fixture
def mock_baseline_initialize():
    secrets = secrets_collection_factory()

    with mock.patch(
            'detect_secrets.main.baseline.initialize',
            return_value=secrets
    ) as mock_initialize:
        yield mock_initialize


class TestMain(object):
    """These are smoke tests for the console usage of detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def test_smoke(self):
        assert main([]) == 0

    def test_scan_basic(self, mock_baseline_initialize):
        assert main(['--scan']) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            '.',
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        assert main('--scan test_data'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            'test_data',
        )

    def test_scan_with_excludes_flag(self, mock_baseline_initialize):
        assert main('--scan --exclude some_pattern_here'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            'some_pattern_here',
            '.',
        )
