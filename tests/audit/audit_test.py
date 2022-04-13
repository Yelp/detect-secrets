import json
import random
from typing import List
from typing import Optional
from unittest import mock

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory
from testing.mocks import mock_named_temporary_file


def test_nothing_to_audit(printer):
    with transient_settings({
        'plugins_used': [
            {'name': 'BasicAuthDetector'},
        ],
    }):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/each_secret.py')

        for _, secret in secrets:
            secret.is_secret = random.choice([True, False])

    run_logic(secrets)
    assert 'Nothing to audit' in printer.message
    assert 'Saving progress' not in printer.message


def test_file_no_longer_exists():
    secrets = SecretsCollection()
    secrets['non-existent'].add(potential_secret_factory())

    run_logic(secrets)


@pytest.mark.parametrize(
    'input_order, expected_order',
    (
        # Basic tests (yes, no, invalid input)
        (
            'nyan',
            [True, False, True],
        ),

        # Skip forwards
        (
            'sn',
            [None, True],
        ),

        # Quit before making a decision
        (
            '',
            [None],
        ),

        # Going back and changing answer
        (
            'nby',
            [False],
        ),
        (
            'ybn',
            [True],
        ),
        (
            'nbs',
            [None],
        ),

        # Going back several steps
        (
            'sybsbbnnn',
            [True, True, True],
        ),
    ),
)
def test_make_decisions(test_baseline, input_order, expected_order):
    assert_labels(run_logic(test_baseline, input_order), expected_order)


@pytest.mark.parametrize(
    'start_state, input_order, expected_order',
    (
        # Leapfrog
        (
            [None, True, None, True],
            'nn',
            [True, True, True, True],
        ),
        (
            [True, None, True],
            'yy',
            [True, False, True, False],
        ),
    ),
)
def test_start_halfway(test_baseline, start_state, input_order, expected_order):
    for index, item in enumerate(test_baseline):
        secret = item[1]
        try:
            if start_state[index] is not None:
                secret.is_secret = start_state[index]
        except IndexError:
            break

    assert_labels(run_logic(test_baseline, input_order), expected_order)


def test_ensure_file_transformers_are_used(printer):
    """
    In this tests, we construct a situation where detect-secrets scan leverages special
    file transformers in order to find a secret, that wouldn't otherwise be found with
    normal line-by-line reading. In doing so, if audit is able to find this secret, it
    can be inferred that it too knows how to use file transformers.
    """
    with transient_settings({
        'plugins_used': [
            {'name': 'Base64HighEntropyString'},
        ],
    }):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.env')
        assert bool(secrets)

    with open('test_data/config.env') as f:
        lines = [line.rstrip() for line in f.readlines()]

    with mock.patch('detect_secrets.audit.io.print_secret_not_found') as m:
        run_logic(secrets, 'y')
        assert not m.called

    line_number = list(secrets['test_data/config.env'])[0].line_number
    assert lines[line_number - 1] in printer.message


def test_fails_if_no_line_numbers_found(printer):
    with transient_settings({
        'plugins_used': [
            {'name': 'Base64HighEntropyString'},
        ],
    }):
        secrets = SecretsCollection()
        secrets.scan_file('test_data/config.env')

    # Remove line numbers
    secrets = baseline.load(baseline.format_for_output(secrets, is_slim_mode=True))

    with mock.patch('detect_secrets.audit.io.clear_screen') as m:
        run_logic(secrets)
        assert not m.called

    assert 'No line numbers found in baseline' in printer.message


def run_logic(
    secrets: SecretsCollection,
    input: Optional[str] = None,
) -> SecretsCollection:
    """
    :param input: if provided, will automatically quit at the end of input string.
        otherwise, will assert that no user input is requested.
    """
    with mock_named_temporary_file() as f:
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        with mock.patch('detect_secrets.audit.io.input') as m:
            if input is not None:
                m.side_effect = list(input) + ['q']

            main(['audit', f.name])

            if input is None:
                assert not m.called

        return baseline.load(baseline.load_from_file(f.name), f.name)


@pytest.fixture
def test_baseline(printer) -> SecretsCollection:
    # We call this through the CLI so it does the plugin initialization for us.
    # It doesn't matter what we scan -- we just need a large enough corpus so that
    # we can perform our tests.
    main(['scan', 'test_data'])
    output = printer.message
    printer.clear()

    return baseline.load(json.loads(output), 'does-not-matter')


def assert_labels(secrets: SecretsCollection, expected: List[Optional[bool]]):
    assert [secret.is_secret for _, secret in secrets][:len(expected)] == expected
