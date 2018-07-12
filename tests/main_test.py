import json
import textwrap
from contextlib import contextmanager

import mock
import pytest

from detect_secrets import main as main_module
from detect_secrets.core import audit as audit_module
from detect_secrets.core.color import BashColor
from detect_secrets.main import main
from testing.factories import secrets_collection_factory
from testing.mocks import Any
from testing.mocks import mock_printer


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

    def test_scan_basic(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['scan']) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            '.',
            False,
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        with mock_stdin():
            assert main('scan test_data'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            'test_data',
            False,
        )

    def test_scan_with_excludes_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert main('scan --exclude some_pattern_here'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            'some_pattern_here',
            '.',
            False,
        )

    def test_scan_with_all_files_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert main('scan --all-files'.split()) == 0

        mock_baseline_initialize.assert_called_once_with(
            Any(tuple),
            None,
            '.',
            True,
        )

    def test_reads_from_stdin(self, mock_merge_baseline):
        with mock_stdin(json.dumps({'key': 'value'})):
            assert main(['scan']) == 0

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )

    def test_reads_old_baseline_from_file(self, mock_merge_baseline):
        with mock_stdin(), mock.patch(
            'detect_secrets.main._read_from_file',
            return_value={'key': 'value'},
        ) as m_read, mock.patch(
            'detect_secrets.main._write_to_file',
        ) as m_write:
            assert main('scan --update old_baseline_file'.split()) == 0
            assert m_read.call_args[0][0] == 'old_baseline_file'
            assert m_write.call_args[0] == ('old_baseline_file', Any(str))

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )

    @pytest.mark.parametrize(
        'exclude_param, expected_regex',
        [
            (
                '',
                '^old_baseline_file$',
            ),
            (
                '--exclude "secrets/.*"',
                'secrets/.*|^old_baseline_file$',
            ),
        ],
    )
    def test_old_baseline_ignored_with_update_flag(
        self,
        mock_baseline_initialize,
        exclude_param,
        expected_regex,
    ):
        with mock_stdin(), mock.patch(
            'detect_secrets.main._read_from_file',
            return_value={},
        ), mock.patch(
            # We don't want to be creating a file during test
            'detect_secrets.main._write_to_file',
        ):
            assert main(
                'scan --update old_baseline_file {}'.format(
                    exclude_param,
                ).split(),
            ) == 0

    @pytest.mark.parametrize(
        'filename, expected_output',
        [
            (
                'test_data/short_files/first_line.py',
                textwrap.dedent("""
                    1:secret = '0123456789a'
                    2:print('second line')
                    3:var = 'third line'
                """)[1:-1],
            ),
            (
                'test_data/short_files/middle_line.yml',
                textwrap.dedent("""
                    1:deploy:
                    2:    user: aaronloo
                    3:    password:
                    4:        secure: thequickbrownfoxjumpsoverthelazydog
                    5:    on:
                    6:        repo: Yelp/detect-secrets
                """)[1:-1],
            ),
            (
                'test_data/short_files/last_line.ini',
                textwrap.dedent("""
                    1:[some section]
                    2:secrets_for_no_one_to_find =
                    3:    hunter2
                    4:    password123
                    5:    0123456789a
                """)[1:-1],
            ),
        ],
    )
    def test_audit_short_file(self, filename, expected_output):
        BashColor.disable_color()

        with mock_stdin(), mock_printer(
            # To extract the baseline output
            main_module,
        ) as printer_shim:
            main(['scan', filename])
            baseline = printer_shim.message

        with mock_stdin(), mock.patch(
            # To pipe in printer_shim
            'detect_secrets.core.audit._get_baseline_from_file',
            return_value=json.loads(baseline),
        ), mock.patch(
            # We don't want to clear the pytest testing screen
            'detect_secrets.core.audit._clear_screen',
        ), mock.patch(
            # Gotta mock it, because tests aren't interactive
            'detect_secrets.core.audit._get_user_decision',
            return_value='s',
        ), mock.patch(
            # We don't want to write an actual file
            'detect_secrets.core.audit._save_baseline_to_file',
        ), mock_printer(
            audit_module,
        ) as printer_shim:
            main('audit will_be_mocked'.split())

            assert printer_shim.message == textwrap.dedent("""
                Secrets Left: 1/1
                Filename:     {}
                ----------
                {}
                ----------
                Saving progress...
            """)[1:].format(
                filename,
                expected_output,
            )

        BashColor.enable_color()


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
