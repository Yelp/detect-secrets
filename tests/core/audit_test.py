from __future__ import absolute_import

from contextlib import contextmanager

import mock
import pytest

from detect_secrets.core import audit


class TestAuditBaseline(object):

    def test_no_baseline(self, mock_printer):
        with self.mock_env(baseline='') as m:
            audit.audit_baseline('will_be_mocked')

            assert not m.called
            assert mock_printer.message == ''

    def test_quit_before_making_decision(self, mock_printer):
        with self.mock_env(['q']):
            audit.audit_baseline('will_be_mocked')

        assert mock_printer.message == (
            'Quitting...\n'
            'Saving progress...\n'
        )

    def test_nothing_to_audit(self, mock_printer):
        modified_baseline = self.baseline.copy()
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = False

        with self.mock_env(baseline=modified_baseline):
            audit.audit_baseline('will_be_mocked')

        assert mock_printer.message == 'Nothing to audit!\n'

    def test_making_decisions(self, mock_printer):
        modified_baseline = self.baseline.copy()
        modified_baseline['results']['filenameA'][0]['is_secret'] = True
        modified_baseline['results']['filenameA'][1]['is_secret'] = False

        self.run_logic(['y', 'n'], modified_baseline)

        assert mock_printer.message == (
            'Saving progress...\n'
        )

    def test_quit_half_way(self, mock_printer):
        modified_baseline = self.baseline.copy()
        modified_baseline['results']['filenameA'][0]['is_secret'] = False

        self.run_logic(['n', 'q'], modified_baseline)

        assert mock_printer.message == (
            'Quitting...\n'
            'Saving progress...\n'
        )

    def test_skip_decision(self, mock_printer):
        modified_baseline = self.baseline.copy()
        modified_baseline['results']['filenameA'][1]['is_secret'] = True

        self.run_logic(['s', 'y'], modified_baseline)

        assert mock_printer.message == (
            'Saving progress...\n'
        )

    @contextmanager
    def run_logic(self, inputs, modified_baseline=None):
        with self.mock_env(inputs) as m:
            audit.audit_baseline('will_be_mocked')

            if not modified_baseline:
                assert m.call_args[0][1] == self.baseline
            else:
                assert m.call_args[0][1] == modified_baseline

    @contextmanager
    def mock_env(self, user_inputs=None, baseline=None):
        if baseline is None:
            baseline = self.baseline

        if not user_inputs:
            user_inputs = []

        with mock.patch.object(
            audit,
            '_get_baseline_from_file',
            return_value=baseline,
        ), mock.patch.object(
            audit,
            '_clear_screen',
        ), mock.patch.object(
            audit,
            '_print_context',
        ), mock_user_input(
            user_inputs,
        ), mock.patch.object(
            audit,
            '_save_baseline_to_file',
        ) as m:
            yield m

    @property
    def baseline(self):
        return {
            'generated_at': 'some timestamp',
            'results': {
                'filenameA': [
                    {
                        'hashed_secret': 'a',
                        'line_number': 122,
                        'type': 'Test Type',
                    },
                    {
                        'hashed_secret': 'b',
                        'line_number': 123,
                        'type': 'Test Type',
                    },
                ],
            },
        }


class TestSecretGenerator(object):

    def test_generates_secret(self):
        count = 0
        for filename, secret, index, total in audit._secret_generator({
            'results': {
                'filenameA': [
                    {
                        'hashed_secret': 'a',
                    },
                    {
                        'hashed_secret': 'b',
                    },
                ],
            },
        }):
            assert filename == 'filenameA'
            if count == 0:
                assert secret['hashed_secret'] == 'a'
            else:
                assert secret['hashed_secret'] == 'b'

            count += 1

    def test_skips_if_already_audited(self):
        for filename, secret, index, total in audit._secret_generator({
            'results': {
                'filenameA': [
                    {
                        'hashed_secret': 'a',
                        'is_secret': False,
                    },
                    {
                        'hashed_secret': 'b',
                    },
                ],
            },
        }):
            assert secret['hashed_secret'] == 'b'


class TestGetUserDecision(object):

    @pytest.mark.parametrize(
        'user_input, expected_value',
        [
            ('y', 'y',),
            ('N', 'n',),
            ('Skip', 's',),
            ('QUIT', 'q',),
        ],
    )
    def test_get_user_decision_valid_input(
        self,
        mock_printer,
        user_input,
        expected_value,
    ):
        with mock.patch.object(audit, 'input', return_value=user_input):
            assert audit._get_user_decision() == expected_value

    def test_get_user_decision_invalid_input(self, mock_printer):
        with mock_user_input(['invalid', 'y']):
            assert audit._get_user_decision() == 'y'

        assert mock_printer.message == ('Invalid input.\n')


@pytest.fixture
def mock_printer():
    class PrinterShim(object):
        def __init__(self):
            self.message = ''

        def add(self, message):
            self.message += message + '\n'

    shim = PrinterShim()
    with mock.patch.object(audit, 'print', shim.add):
        yield shim


@contextmanager
def mock_user_input(inputs):
    """
    :type inputs: list
    :param inputs: list of user choices
    """
    current_case = {'index': 0}     # needed, because py2 doesn't have nonlocal

    def _wrapped(*args, **kwargs):
        output = inputs[current_case['index']]
        current_case['index'] += 1

        return output

    with mock.patch.object(audit, 'input', _wrapped):
        yield
