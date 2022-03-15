from contextlib import contextmanager
from copy import deepcopy

import mock
import pytest

from detect_secrets.core import audit as audit_module
from detect_secrets.core.report.constants import ReportExitCode
from detect_secrets.main import main
from testing.baseline import baseline


@pytest.fixture
def mock_print_table_report():
    with mock.patch(
        'detect_secrets.core.report.report.print_table_report',
    ) as m:
        yield m


@pytest.fixture
def mock_print_stats():
    with mock.patch(
        'detect_secrets.core.report.report.print_stats',
    ) as m:
        yield m


@pytest.fixture
def mock_print_summary():
    with mock.patch(
        'detect_secrets.core.report.report.print_summary',
    ) as m:
        yield m


@pytest.fixture
def mock_print_json_report():
    with mock.patch(
        'detect_secrets.core.report.report.print_json_report',
    ) as m:
        yield m


@pytest.fixture
def mock_fail_on_unaudited():
    with mock.patch(
        'detect_secrets.core.report.report.fail_on_unaudited',
        return_value=(ReportExitCode.PASS.value, []),
    ) as m:
        yield m


@pytest.fixture
def mock_fail_on_live():
    with mock.patch(
        'detect_secrets.core.report.report.fail_on_live',
        return_value=(ReportExitCode.PASS.value, []),
    ) as m:
        yield m


@pytest.fixture
def mock_fail_on_audited_real():
    with mock.patch(
        'detect_secrets.core.report.report.fail_on_audited_real',
        return_value=(ReportExitCode.PASS.value, []),
    ) as m:
        yield m


class TestReport:
    """
    These are smoke tests for the console usage of the detect_secrets
    report feature.
    """

    @contextmanager
    def mock_env(self, baseline=None):
        with mock.patch.object(
            # We mock this, so we don't need to do any file I/O.
            audit_module,
            '_get_baseline_from_file',
            return_value=baseline or self.baseline,
        ) as m:
            yield m

    @property
    def baseline(self):
        return baseline

    def test_fail_on_unaudited_mutually_inclusive_with_report(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --fail-on-unaudited fileA'.split())

        captured = capsys.readouterr()

        assert 'argument --fail-on-unaudited: not allowed without argument --report' in captured.err

    def test_fail_on_live_mutually_inclusive_with_report(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --fail-on-live fileA'.split())

        captured = capsys.readouterr()

        assert 'argument --fail-on-live: not allowed without argument --report' in captured.err

    def test_fail_on_audited_real_mutually_inclusive_with_report(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --fail-on-audited-real fileA'.split())

        captured = capsys.readouterr()

        assert (
            'argument --fail-on-audited-real: not allowed without argument --report' in captured.err
        )

    def test_omit_instructions_mutually_inclusive_with_report(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --omit-instructions fileA'.split())

        captured = capsys.readouterr()

        assert 'argument --omit-instructions: not allowed without argument --report' in captured.err

    def test_json_mutually_inclusive_with_report(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --json fileA'.split())

        captured = capsys.readouterr()

        assert 'argument --json: not allowed without argument --report' in captured.err

    def test_json_mutually_exclusive_with_omit_instructions(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --report --json --omit-instructions fileA'.split())

        captured = capsys.readouterr()

        assert 'argument --omit-instructions: not allowed with argument --json' in captured.err

    def test_report_without_file(self, capsys):
        with pytest.raises(SystemExit):
            main('audit --report'.split())

        captured = capsys.readouterr()

        assert 'the following arguments are required: filename' in captured.err

    def test_default_report_prints_table_output(
        self,
        mock_print_stats,
        mock_print_table_report,
        mock_print_summary,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report fileA'.split())

        mock_print_stats.assert_called()
        mock_print_table_report.assert_called()
        mock_print_summary.assert_called()

    def test_default_report_runs_all_checks(
        self,
        mock_fail_on_unaudited,
        mock_fail_on_live,
        mock_fail_on_audited_real,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report fileA'.split())

        mock_fail_on_unaudited.assert_called()
        mock_fail_on_live.assert_called()
        mock_fail_on_audited_real.assert_called()

    def test_default_report_always_exits_with_code_zero(self):
        with self.mock_env(), pytest.raises(SystemExit) as context:
            main('audit --report fileA'.split())

        assert context.type == SystemExit
        assert context.value.code == ReportExitCode.PASS.value

    def test_json_report(self, mock_print_json_report):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --json fileA'.split())

        mock_print_json_report.assert_called()

    def test_json_report_prints_json_output(
        self,
        mock_print_json_report,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --json fileA'.split())

        mock_print_json_report.assert_called()

    def test_default_json_report_executes_all_conditions(
        self,
        mock_fail_on_unaudited,
        mock_fail_on_live,
        mock_fail_on_audited_real,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --json fileA'.split())

        mock_fail_on_unaudited.assert_called()
        mock_fail_on_live.assert_called()
        mock_fail_on_audited_real.assert_called()

    def test_default_json_report_always_exits_with_code_zero(self):
        with self.mock_env(), pytest.raises(SystemExit) as context:
            main('audit --report --json fileA'.split())

        assert context.type == SystemExit
        assert context.value.code == ReportExitCode.PASS.value

    def test_json_report_with_all_fail_conditions_exits_with_non_zero_upon_failure(self):
        with self.mock_env(), pytest.raises(SystemExit) as context:
            main(
                'audit --report --json --fail-on-unaudited'
                ' --fail-on-live --fail-on-audited-real fileA'.split(),
            )

        assert context.type == SystemExit
        assert context.value.code == ReportExitCode.FAIL.value

    def test_report_with_all_fail_on_conditions_executes_all_conditions(
        self,
        mock_fail_on_unaudited,
        mock_fail_on_live,
        mock_fail_on_audited_real,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main(
                'audit --report --fail-on-unaudited --fail-on-live'
                ' --fail-on-audited-real fileA'.split(),
            )

        mock_fail_on_unaudited.assert_called()
        mock_fail_on_live.assert_called()
        mock_fail_on_audited_real.assert_called()

    def test_report_with_all_fail_on_conditions_exits_with_non_zero_upon_failure(self):
        modified_baseline = deepcopy(self.baseline)
        print(self.baseline)
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = None
        modified_baseline['results']['filenameB'][0]['is_verified'] = True

        with self.mock_env(baseline=modified_baseline), pytest.raises(SystemExit) as context:
            main(
                'audit --report --fail-on-unaudited --fail-on-live'
                ' --fail-on-audited-real fileA'.split(),
            )

        assert context.type == SystemExit
        assert context.value.code == ReportExitCode.FAIL.value

    def test_report_fail_on_live_only(
        self,
        mock_fail_on_live,
        mock_fail_on_unaudited,
        mock_fail_on_audited_real,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --fail-on-live fileA'.split())

        mock_fail_on_live.assert_called()
        mock_fail_on_unaudited.assert_not_called()
        mock_fail_on_audited_real.assert_not_called()

    def test_report_fail_on_audited_real_only(
        self,
        mock_fail_on_audited_real,
        mock_fail_on_unaudited,
        mock_fail_on_live,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --fail-on-audited-real fileA'.split())

        mock_fail_on_audited_real.assert_called()
        mock_fail_on_unaudited.assert_not_called()
        mock_fail_on_live.assert_not_called()

    def test_report_fail_on_unaudited_only(
        self,
        mock_fail_on_unaudited,
        mock_fail_on_audited_real,
        mock_fail_on_live,
    ):
        with self.mock_env(), pytest.raises(SystemExit):
            main('audit --report --fail-on-unaudited fileA'.split())

        mock_fail_on_unaudited.assert_called()
        mock_fail_on_audited_real.assert_not_called()
        mock_fail_on_live.assert_not_called()
