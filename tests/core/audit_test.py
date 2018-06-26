from __future__ import absolute_import

import string
import textwrap
from contextlib import contextmanager

import mock
import pytest

from detect_secrets.core import audit
from detect_secrets.core.color import BashColor
from testing.factories import potential_secret_factory


class TestAuditBaseline(object):

    def test_no_baseline(self, mock_printer):
        with self.mock_env(baseline='') as m:
            audit.audit_baseline('will_be_mocked')

            assert not m.called
            assert mock_printer.message == ''

    def test_quit_before_making_decision(self, mock_printer):
        with self.mock_env(['q']) as m:
            audit.audit_baseline('will_be_mocked')

            assert m.call_args[0][1] == self.baseline

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
            # We mock this, so we don't need to do any file I/O.
            audit,
            '_get_baseline_from_file',
            return_value=baseline,
        ), mock.patch.object(
            # We mock this, because we don't really care about clearing
            # screens for test cases.
            audit,
            '_clear_screen',
        ), mock.patch.object(
            # Tests for this fall under a different test suite.
            audit,
            '_print_context',
        ), mock_user_input(
            user_inputs,
        ), mock.patch.object(
            # We mock this, so we don't need to do any file I/O.
            audit,
            '_save_baseline_to_file',
        ) as m:
            yield m

    @property
    def baseline(self):
        return {
            'generated_at': 'some timestamp',
            'plugins_used': [
                {
                    'name': 'TestPlugin',
                },
            ],
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
                'filenameB': [
                    {
                        'hashed_secret': 'c',
                        'line_number': 123,
                        'type': 'Test Type',
                    },
                ],
            },
        }


class TestPrintContext(object):

    def setup(self):
        BashColor.disable_color()

    def teardown(self):
        BashColor.enable_color()

    def run_logic(self, secret=None, secret_lineno=15, settings=None):
        # Setup default arguments
        if not secret:
            secret = potential_secret_factory(
                type_='Private Key',
                filename='filenameA',
                secret='BEGIN PRIVATE KEY',
                lineno=secret_lineno,
            ).json()

        if not settings:
            settings = [
                {
                    'name': 'PrivateKeyDetector',
                },
            ]

        audit._print_context(
            secret['filename'],
            secret,
            count=1,
            total=2,
            plugin_settings=settings,
        )

    @contextmanager
    def _mock_sed_call(
        self,
        start_line=10,
        secret_line=15,
        end_line=20,
        line_containing_secret='BEGIN PRIVATE KEY',
    ):
        with mock.patch(
            'detect_secrets.core.audit.subprocess',
        ) as m:
            m.check_output.return_value = '{}{}{}'.format(
                self._make_string_into_individual_lines(
                    string.ascii_letters[:(secret_line - start_line)],
                ),
                line_containing_secret + '\n',
                self._make_string_into_individual_lines(
                    string.ascii_letters[:(end_line - secret_line)][::-1],
                ),
            ).encode()

            yield m.check_output

    @staticmethod
    def _make_string_into_individual_lines(string):
        return ''.join(
            map(
                lambda x: x + '\n',
                string,
            ),
        )

    def test_basic(self, mock_printer):
        with self._mock_sed_call(
            start_line=10,
            secret_line=15,
            end_line=20,
            line_containing_secret='-----BEGIN PRIVATE KEY-----',
        ) as sed_call:
            self.run_logic()

            assert sed_call.call_args[0][0] == 'sed -n 10,20p filenameA'.split()

        assert mock_printer.message == textwrap.dedent("""
            Secrets Left: 1/2
            Filename:     filenameA
            ----------
            10:a
            11:b
            12:c
            13:d
            14:e
            15:-----BEGIN PRIVATE KEY-----
            16:e
            17:d
            18:c
            19:b
            20:a
            ----------

        """)[1:-1]

    def test_secret_at_top_of_file(self, mock_printer):
        with self._mock_sed_call(
            start_line=1,
            secret_line=1,
            end_line=6,
            line_containing_secret='-----BEGIN PRIVATE KEY-----',
        ) as sed_call:
            self.run_logic(
                secret_lineno=1,
            )

            assert sed_call.call_args[0][0] == 'sed -n 1,6p filenameA'.split()

        assert mock_printer.message == textwrap.dedent("""
            Secrets Left: 1/2
            Filename:     filenameA
            ----------
            1:-----BEGIN PRIVATE KEY-----
            2:e
            3:d
            4:c
            5:b
            6:a
            ----------

        """)[1:-1]

    def test_secret_not_found(self, mock_printer):
        with self._mock_sed_call(), pytest.raises(
            audit.SecretNotFoundOnSpecifiedLineError,
        ):
            self.run_logic(
                secret=potential_secret_factory(
                    type_='Private Key',
                    filename='filenameA',
                    secret='BEGIN RSA PRIVATE KEY',
                    lineno=15,
                ).json(),
            )

        assert mock_printer.message == textwrap.dedent("""
            Secrets Left: 1/2
            Filename:     filenameA
            ----------
            ERROR: Secret not found on specified line number!
            Try recreating your baseline to fix this issue.
            ----------

        """)[1:-1]

    def test_secret_in_yaml_file(self, mock_printer):
        with self._mock_sed_call(
            line_containing_secret='api key: 123456789a',
        ):
            self.run_logic(
                secret=potential_secret_factory(
                    type_='Hex High Entropy String',
                    filename='filenameB',
                    secret='123456789a',
                    lineno=15,
                ).json(),
                settings=[
                    {
                        'name': 'HexHighEntropyString',
                        'hex_limit': 3,
                    },
                ],
            )

        assert mock_printer.message == textwrap.dedent("""
            Secrets Left: 1/2
            Filename:     filenameB
            ----------
            10:a
            11:b
            12:c
            13:d
            14:e
            15:api key: 123456789a
            16:e
            17:d
            18:c
            19:b
            20:a
            ----------

        """)[1:-1]


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

    @pytest.mark.parametrize(
        'prompt_secret_decision, expected_output',
        [
            (
                True,
                'Is this a valid secret? (y)es, (n)o, (s)kip, (q)uit: ',
            ),
            (
                False,
                'What would you like to do? (s)kip, (q)uit: ',
            ),
        ],
    )
    def test_input_message(self, prompt_secret_decision, expected_output):
        with mock_user_input(['q']) as m:
            audit._get_user_decision(prompt_secret_decision=prompt_secret_decision)

            assert m.message == expected_output


@pytest.fixture
def mock_printer():
    class PrinterShim(object):
        def __init__(self):
            self.message = ''

        def add(self, message):
            self.message += str(message) + '\n'

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

    class InputShim(object):
        def __init__(self):
            self.message = ''

        def get_user_input(self, *args, **kwargs):
            self.message += args[0]

            output = inputs[current_case['index']]
            current_case['index'] += 1

            return output

    shim = InputShim()
    with mock.patch.object(audit, 'input', shim.get_user_input):
        yield shim
