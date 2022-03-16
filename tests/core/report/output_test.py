from contextlib import contextmanager
from copy import deepcopy

import mock
import pytest

from detect_secrets.core import audit
from detect_secrets.core.color import AnsiColor
from detect_secrets.core.color import colorize
from detect_secrets.core.report.constants import ReportSecretType
from detect_secrets.core.report.output import get_stats
from detect_secrets.core.report.output import print_json_report
from detect_secrets.core.report.output import print_stats
from detect_secrets.core.report.output import print_summary
from detect_secrets.core.report.output import print_table_report
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
        with mock.patch.object(
            # We mock this, so we don't need to do any file I/O.
            audit,
            '_get_baseline_from_file',
            return_value=baseline or self.baseline,
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

    def test_print_stats_failed_conditions_multiple_secrets_per_condition(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = None
        modified_baseline['results']['filenameA'].append(
            {
                'hashed_secret': 'd',
                'line_number': 150,
                'type': 'Private key',
                'is_secret': None,
            },
        )
        modified_baseline['results']['filenameB'][0]['is_verified'] = True
        modified_baseline['results']['filenameB'].append(
            {
                'hashed_secret': 'e',
                'line_number': 185,
                'type': 'Hex High Entropy String',
                'is_verified': True,
            },
        )
        modified_baseline['results']['filenameB'].append(
            {
                'hashed_secret': 'f',
                'line_number': 200,
                'type': 'Hex High Entropy String',
                'is_secret': True,
            },
        )

        live_secrets_fixture.append(
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': baseline_filename,
                'line': 180,
                'type': 'Private key',
            },
        )
        unaudited_secrets_fixture.append(
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': baseline_filename,
                'line': 150,
                'type': 'Hex High Entropy String',
            },
        )
        audited_real_secrets_fixture.append(
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': baseline_filename,
                'line': 200,
                'type': 'Hex High Entropy String',
            },
        )

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
        ) + ' Found {} live secrets, {} unaudited secrets,'.format(
            colorize(len(live_secrets_fixture), AnsiColor.BOLD),
            colorize(len(unaudited_secrets_fixture), AnsiColor.BOLD),
        ) + ' and {} secrets that were audited as real.\n\n'.format(
            colorize(len(audited_real_secrets_fixture), AnsiColor.BOLD),
        )

    def test_print_stats_failed_conditions_zero_and_multiple_secrets_per_condition(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = False
        modified_baseline['results']['filenameA'][1]['is_secret'] = False
        modified_baseline['results']['filenameB'][0]['is_verified'] = True

        unaudited_secrets_fixture = audited_real_secrets_fixture = []

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
        ) + ' Found {} live secret, {} unaudited secrets,'.format(
            colorize(len(live_secrets_fixture), AnsiColor.BOLD),
            colorize(len(unaudited_secrets_fixture), AnsiColor.BOLD),
        ) + ' and {} secrets that were audited as real.\n\n'.format(
            colorize(len(audited_real_secrets_fixture), AnsiColor.BOLD),
        )

    def test_print_report_table_no_failed_conditions(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        live_secrets_fixture = unaudited_secrets_fixture = audited_real_secrets_fixture = []

        print_table_report(
            live_secrets_fixture,
            unaudited_secrets_fixture,
            audited_real_secrets_fixture,
        )

        captured = capsys.readouterr()

        assert captured.out == ''

    def test_print_report_table_failed_conditions(self, capsys):
        live_secrets_fixture = [
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameA',
                'line': 90,
                'type': 'Test Type',
            },
        ]
        unaudited_secrets_fixture = [
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': 'filenameA',
                'line': 120,
                'type': 'Test Type',
            },
        ]
        audited_real_secrets_fixture = [
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': 'filenameB',
                'line': 60,
                'type': 'Test Type',
            },
        ]

        print_table_report(
            live_secrets_fixture,
            unaudited_secrets_fixture,
            audited_real_secrets_fixture,
        )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """Failed Condition    Secret Type    Filename      Line
------------------  -------------  ----------  ------
Live                Test Type      filenameA       90
Unaudited           Test Type      filenameA      120
Audited as real     Test Type      filenameB       60\n"""
        )

    def test_print_json_report_no_failed_conditions(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        live_secrets_fixture = unaudited_secrets_fixture = audited_real_secrets_fixture = []

        with self.mock_env():
            print_json_report(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """{
    "stats": {
        "reviewed": 3,
        "live": 0,
        "unaudited": 0,
        "audited_real": 0
    },
    "secrets": []
}\n"""
        )

    def test_print_json_report_failed_conditions(
        self,
        capsys,
        live_secrets_fixture,
        unaudited_secrets_fixture,
        audited_real_secrets_fixture,
    ):
        with self.mock_env():
            print_json_report(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                True,
                True,
            )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """{
    "stats": {
        "reviewed": 3,
        "live": 1,
        "unaudited": 1,
        "audited_real": 1
    },
    "secrets": [
        {
            "failed_condition": "Live",
            "filename": "will_be_mocked",
            "line": 90,
            "type": "Private key"
        },
        {
            "failed_condition": "Unaudited",
            "filename": "will_be_mocked",
            "line": 120,
            "type": "Hex High Entropy String"
        },
        {
            "failed_condition": "Audited as real",
            "filename": "will_be_mocked",
            "line": 60,
            "type": "Hex High Entropy String"
        }
    ]
}\n"""
        )

    def test_print_json_report_only_live(
        self, capsys, live_secrets_fixture, unaudited_secrets_fixture, audited_real_secrets_fixture,
    ):
        with self.mock_env():
            print_json_report(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                True,
                False,
                False,
            )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """{
    "stats": {
        "reviewed": 3,
        "live": 1
    },
    "secrets": [
        {
            "failed_condition": "Live",
            "filename": "will_be_mocked",
            "line": 90,
            "type": "Private key"
        }
    ]
}\n"""
        )

    def test_print_json_report_only_unaudited(
        self, capsys, live_secrets_fixture, unaudited_secrets_fixture, audited_real_secrets_fixture,
    ):
        with self.mock_env():
            print_json_report(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                False,
                True,
                False,
            )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """{
    "stats": {
        "reviewed": 3,
        "unaudited": 1
    },
    "secrets": [
        {
            "failed_condition": "Unaudited",
            "filename": "will_be_mocked",
            "line": 120,
            "type": "Hex High Entropy String"
        }
    ]
}\n"""
        )

    def test_print_json_report_only_audited_true(
        self, capsys, live_secrets_fixture, unaudited_secrets_fixture, audited_real_secrets_fixture,
    ):
        with self.mock_env():
            print_json_report(
                live_secrets_fixture,
                unaudited_secrets_fixture,
                audited_real_secrets_fixture,
                baseline_filename,
                False,
                False,
                True,
            )

        captured = capsys.readouterr()

        assert (
            captured.out
            == """{
    "stats": {
        "reviewed": 3,
        "audited_real": 1
    },
    "secrets": [
        {
            "failed_condition": "Audited as real",
            "filename": "will_be_mocked",
            "line": 60,
            "type": "Hex High Entropy String"
        }
    ]
}\n"""
        )

    def test_print_summary_no_failed_conditions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 0

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            True,
            True,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '{}\n\n{}\n\n{}\n\n'.format(
            colorize('\t- No unaudited secrets were found', AnsiColor.BOLD),
            colorize('\t- No live secrets were found', AnsiColor.BOLD),
            colorize('\t- No secrets that were audited as real were found', AnsiColor.BOLD),
        )

    def test_print_summary_no_failed_conditions_omit_instructions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 0

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            True,
            True,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '{}\n\n'.format(
            colorize('\t- No unaudited secrets were found', AnsiColor.BOLD),
        ) + '{}\n\n'.format(
            colorize('\t- No live secrets were found', AnsiColor.BOLD),
        ) + '{}\n\n'.format(
            colorize('\t- No secrets that were audited as real were found', AnsiColor.BOLD),
        )

    def test_print_summary_all_failed_conditions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            True,
            True,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n'.format(
            colorize('\t- Unaudited secrets were found', AnsiColor.BOLD),
            '\n\t\tRun detect-secrets audit {}, and audit all potential secrets.'.format(
                baseline_filename,
            ),
            colorize('\t- Live secrets were found', AnsiColor.BOLD),
            '\n\t\tRevoke all live secrets and remove them from the codebase.'
            ' Afterwards, run detect-secrets scan --update {} to re-scan.'.format(
                baseline_filename,
            ),
            colorize('\t- Audited true secrets were found', AnsiColor.BOLD),
            '\n\t\tRemove secrets meeting this condition from the codebase,'
            ' and run detect-secrets scan --update {} to re-scan.'.format(
                baseline_filename,
            ),
            '\nFor additional help, run detect-secrets audit --help.\n',
        )

    def test_print_summary_all_failed_conditions_omit_instructions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            True,
            True,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n\n{}\n\n{}\n\n'.format(
            colorize('\t- Unaudited secrets were found', AnsiColor.BOLD),
            colorize('\t- Live secrets were found', AnsiColor.BOLD),
            colorize('\t- Audited true secrets were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_live_pass(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 0

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            False,
            False,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '{}\n\n'.format(
            colorize('\t- No live secrets were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_unaudited_pass(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 0

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            True,
            False,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '{}\n\n'.format(
            colorize('\t- No unaudited secrets were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_audited_real_pass(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 0

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            False,
            True,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '{}\n\n'.format(
            colorize('\t- No secrets that were audited as real were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_live_fail(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            False,
            False,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n{}\n{}\n'.format(
            colorize('\t- Live secrets were found', AnsiColor.BOLD),
            '\n\t\tRevoke all live secrets and remove them from the codebase.'
            ' Afterwards, run detect-secrets scan --update {} to re-scan.'.format(
                baseline_filename,
            ),
            '\nFor additional help, run detect-secrets audit --help.\n',
        )

    def test_print_summary_only_live_fail_omit_instructions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            True,
            False,
            False,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n\n'.format(
            colorize('\t- Live secrets were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_unaudited_fail(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            True,
            False,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n{}\n{}\n'.format(
            colorize('\t- Unaudited secrets were found', AnsiColor.BOLD),
            '\n\t\tRun detect-secrets audit {}, and audit all potential secrets.'.format(
                baseline_filename,
            ),
            '\nFor additional help, run detect-secrets audit --help.\n',
        )

    def test_print_summary_only_unaudited_fail_omit_instructions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            True,
            False,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n\n'.format(
            colorize('\t- Unaudited secrets were found', AnsiColor.BOLD),
        )

    def test_print_summary_only_audited_real_fail(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            False,
            True,
            False,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n{}\n{}\n'.format(
            colorize('\t- Audited true secrets were found', AnsiColor.BOLD),
            '\n\t\tRemove secrets meeting this condition from the codebase,'
            ' and run detect-secrets scan --update {} to re-scan.'.format(
                baseline_filename,
            ),
            '\nFor additional help, run detect-secrets audit --help.\n',
        )

    def test_print_summary_only_audited_real_fail_omit_instructions(self, capsys):
        unaudited_return_code = live_return_code = audited_real_return_code = 1

        print_summary(
            unaudited_return_code,
            live_return_code,
            audited_real_return_code,
            baseline_filename,
            False,
            False,
            True,
            True,
        )

        captured = capsys.readouterr()

        assert captured.out == '\nFailed conditions:\n\n{}\n\n'.format(
            colorize('\t- Audited true secrets were found', AnsiColor.BOLD),
        )
