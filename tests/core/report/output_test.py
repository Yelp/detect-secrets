from contextlib import contextmanager
from copy import deepcopy

import mock
import pytest

from detect_secrets.core import audit
from detect_secrets.core.color import AnsiColor
from detect_secrets.core.color import colorize
from detect_secrets.core.report.constants import ReportSecretType
from detect_secrets.core.report.output import get_stats
from detect_secrets.core.report.output import print_stats
from testing.baseline import baseline
from testing.baseline import baseline_filename


@pytest.fixture
def live_secrets_fixture():
    live_secrets = [
        {
            'failed_condition': ReportSecretType.LIVE.value,
            'filename': baseline_filename,
            'line': 90,
            'type': 'Private key',
        },
    ]
    return live_secrets


@pytest.fixture
def unaudited_secrets_fixture():
    unaudited_secrets = [
        {
            'failed_condition': ReportSecretType.UNAUDITED.value,
            'filename': baseline_filename,
            'line': 120,
            'type': 'Hex High Entropy String',
        },
    ]
    return unaudited_secrets


@pytest.fixture
def audited_real_secrets_fixture():
    audited_real_secrets = [
        {
            'failed_condition': ReportSecretType.AUDITED_REAL.value,
            'filename': baseline_filename,
            'line': 60,
            'type': 'Hex High Entropy String',
        },
    ]

    return audited_real_secrets


class TestReportOutput:
    @contextmanager
    def mock_env(self, baseline=None):
        if baseline is None:
            baseline = self.baseline

        with mock.patch.object(
            # We mock this, so we don't need to do any file I/O.
            audit,
            '_get_baseline_from_file',
            return_value=baseline,
        ) as m:
            yield m

    @property
    def baseline(self):
        return baseline

    def test_get_stats_no_failed_conditions(
        self,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        with self.mock_env():
            stats = get_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        assert stats == {
            'reviewed': len(secrets),
            'live': len(live_secrets_fixture),
            'unaudited': len(unaudited_secrets_fixture),
            'audited_real': len(audited_real_secrets_fixture),
        }

    def test_get_stats_all_failed_conditions(
        self,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):

        with self.mock_env():
            stats = get_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        assert stats == {
            'reviewed': len(secrets),
            'live': len(live_secrets_fixture),
            'unaudited': len(unaudited_secrets_fixture),
            'audited_real': len(audited_real_secrets_fixture),
        }

    def test_get_stats_live_only(
        self,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):

        with self.mock_env():
            stats = get_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                False,
                False,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        assert stats == {
            'reviewed': len(secrets),
            'live': len(live_secrets_fixture),
        }

    def test_get_stats_unaudited_only(
        self,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):

        with self.mock_env():
            stats = get_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                False,
                True,
                False,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        assert stats == {
            'reviewed': len(secrets),
            'unaudited': len(unaudited_secrets_fixture),
        }

    def test_get_stats_audited_real_only(
        self,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):

        with self.mock_env():
            stats = get_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                False,
                False,
                True,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        assert stats == {
            'reviewed': len(secrets),
            'audited_real': len(audited_real_secrets_fixture),
        }

    def test_print_stats_no_failed_conditions(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        live_secrets_fixture = unaudited_secrets_fixture = audited_real_secrets_fixture = []

        with self.mock_env():
            print_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        captured = capsys.readouterr()

        assert captured.out == (
            '\n{} potential secrets in {} were reviewed.'
            ' All checks have passed.\n\n'.format(
                colorize(len(secrets), AnsiColor.BOLD),
                colorize(baseline_filename, AnsiColor.BOLD),
            )
        )

    def test_print_stats_failed_conditions_one_secret_per_condition(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = None
        modified_baseline['results']['filenameB'][0]['is_verified'] = True

        with self.mock_env(baseline=modified_baseline):
            print_stats(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )
            secrets = audit.get_secrets_list_from_file(baseline_filename)

        captured = capsys.readouterr()

        assert captured.out == '\n{} potential secrets in {} were reviewed.'.format(
            colorize(len(secrets), AnsiColor.BOLD),
            colorize(baseline_filename, AnsiColor.BOLD),
        ) + ' Found {} live secret, {} unaudited secret,'.format(
            colorize(len(live_secrets_fixture), AnsiColor.BOLD),
            colorize(len(unaudited_secrets_fixture), AnsiColor.BOLD),
        ) + ' and {} secret that was audited as real.\n\n'.format(
            colorize(len(audited_real_secrets_fixture), AnsiColor.BOLD),
        )
