from contextlib import contextmanager
from copy import deepcopy

import mock

from detect_secrets.core import audit
from detect_secrets.core.report.conditions import fail_on_audited_real
from detect_secrets.core.report.conditions import fail_on_live
from detect_secrets.core.report.conditions import fail_on_unaudited
from detect_secrets.core.report.constants import ReportExitCode
from detect_secrets.core.report.constants import ReportSecretType
from testing.baseline import baseline
from testing.baseline import baseline_filename


class TestReportConditions:

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

    def test_unaudited_pass_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = False
        modified_baseline['results']['filenameA'][1]['is_secret'] = False
        modified_baseline['results']['filenameB'][0]['is_secret'] = False

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_unaudited(baseline_filename)

        assert return_code == ReportExitCode.PASS.value
        assert len(secrets) == 0

    def test_unaudited_fail_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = None
        modified_baseline['results']['filenameA'][1]['is_secret'] = None
        modified_baseline['results']['filenameB'][0]['is_secret'] = None

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_unaudited(baseline_filename)

        expected_secrets = [
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][1]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': 'filenameB',
                'line': modified_baseline['results']['filenameB'][0]['line_number'],
                'type': 'Test Type',
            },
        ]

        assert return_code == ReportExitCode.FAIL.value
        assert len(secrets) == len(expected_secrets)
        assert [i for i in secrets if i not in expected_secrets] == []

    def test_live_pass_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_verified'] = False
        modified_baseline['results']['filenameA'][1]['is_verified'] = False
        modified_baseline['results']['filenameB'][0]['is_verified'] = False

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_live(baseline_filename)

        assert return_code == ReportExitCode.PASS.value
        assert len(secrets) == 0

    def test_live_fail_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_verified'] = True
        modified_baseline['results']['filenameA'][1]['is_verified'] = True
        modified_baseline['results']['filenameB'][0]['is_verified'] = True

        expected_secrets = [
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][1]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameB',
                'line': modified_baseline['results']['filenameB'][0]['line_number'],
                'type': 'Test Type',
            },
        ]

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_live(baseline_filename)

        assert return_code == ReportExitCode.FAIL.value
        assert len(secrets) == len(expected_secrets)
        assert [i for i in secrets if i not in expected_secrets] == []

    def test_audited_real_pass_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = False
        modified_baseline['results']['filenameA'][1]['is_secret'] = False
        modified_baseline['results']['filenameB'][0]['is_secret'] = False

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_audited_real(baseline_filename)

        assert return_code == ReportExitCode.PASS.value
        assert len(secrets) == 0

    def test_audited_real_fail_case(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = True
        modified_baseline['results']['filenameB'][0]['is_secret'] = True

        expected_secrets = [
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][1]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': 'filenameB',
                'line': modified_baseline['results']['filenameB'][0]['line_number'],
                'type': 'Test Type',
            },
        ]

        with self.mock_env(baseline=modified_baseline):
            (return_code, secrets) = fail_on_audited_real(baseline_filename)

        assert return_code == ReportExitCode.FAIL.value
        assert len(secrets) == len(expected_secrets)
        assert [i for i in secrets if i not in expected_secrets] == []

    def test_fail_live_and_audited_real_conditions_with_same_secret(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][0]['is_verified'] = True

        expected_secrets = [
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.AUDITED_REAL.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
        ]

        with self.mock_env(baseline=modified_baseline):
            (live_return_code, live_secrets) = fail_on_live(baseline_filename)
            (audited_real_return_code, audited_real_secrets) = fail_on_audited_real(
                baseline_filename,
            )

        secrets = live_secrets + audited_real_secrets

        assert audited_real_return_code == live_return_code == ReportExitCode.FAIL.value
        assert len(secrets) == len(expected_secrets)
        assert [i for i in secrets if i not in expected_secrets] == []

    def test_fail_live_and_unaudited_conditions_with_same_secret(self):
        modified_baseline = deepcopy(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = None
        modified_baseline['results']['filenameA'][0]['is_verified'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = False
        modified_baseline['results']['filenameB'][0]['is_secret'] = False

        expected_secrets = [
            {
                'failed_condition': ReportSecretType.LIVE.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
            {
                'failed_condition': ReportSecretType.UNAUDITED.value,
                'filename': 'filenameA',
                'line': modified_baseline['results']['filenameA'][0]['line_number'],
                'type': 'Test Type',
            },
        ]

        with self.mock_env(baseline=modified_baseline):
            (live_return_code, live_secrets) = fail_on_live(baseline_filename)
            (unaudited_return_code, unaudited_secrets) = fail_on_unaudited(baseline_filename)

        secrets = live_secrets + unaudited_secrets

        assert unaudited_return_code == live_return_code == ReportExitCode.FAIL.value
        assert len(secrets) == len(expected_secrets)
        assert [i for i in secrets if i not in expected_secrets] == []
