import re
from contextlib import contextmanager
from unittest import mock

import pytest

from detect_secrets.audit.io import InputOptions
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from testing.factories import potential_secret_factory as original_potential_secret_factory
from testing.mocks import mock_named_temporary_file


def potential_secret_factory(secret: str, **kwargs):
    output = original_potential_secret_factory(
        # We just need a legitimate type, it doesn't matter what.
        type=BasicAuthDetector.secret_type,
        secret=secret,
        **kwargs,
    )

    # Change the hash, so we can control the order.
    output.secret_hash = secret
    return output


def test_comparing_same_file(printer):
    main(['audit', '--diff', '.secrets.baseline', '.secrets.baseline'])

    assert printer.message.strip() == 'This is the same file!'


def test_same_secrets_are_skipped(mock_user_decision):
    baselineA = get_secrets(potential_secret_factory('a'))
    baselineB = get_secrets(potential_secret_factory('a'))

    with allow_fake_files():
        run_logic(baselineA, baselineB)

    assert not mock_user_decision.called


@pytest.mark.parametrize(
    'secretsA, secretsB, expected_order',
    (
        # No secrets in one.
        (
            [],
            [
                potential_secret_factory('a'),
                potential_secret_factory('b'),
            ],
            'RR',
        ),
        (
            [
                potential_secret_factory('a'),
            ],
            [],
            'L',
        ),

        # Finish a file, before proceeding
        (
            [
                potential_secret_factory('a', filename='b'),
                potential_secret_factory('a', filename='a'),
                potential_secret_factory('b', filename='a'),
                potential_secret_factory('c', filename='a'),
            ],
            [
                potential_secret_factory('b', filename='a'),
                potential_secret_factory('a', filename='b'),
                potential_secret_factory('b', filename='b'),
            ],

            # We should have removed `a`, `c` and then added `e`
            'LLR',
        ),

        # Show in line order
        (
            [
                potential_secret_factory('a', line_number=4),
            ],
            [
                potential_secret_factory('a', line_number=2),
            ],
            'RL',
        ),
    ),
)
def test_order(printer, secretsA, secretsB, expected_order):
    baselineA = get_secrets(*secretsA)
    baselineB = get_secrets(*secretsB)

    # It is difficult to have fine-grained testing, and actually use real files.
    # Therefore, let's just mock out this function so we can work with fake files.
    with allow_fake_files():
        run_logic(baselineA, baselineB)

    assert parse_ordering(printer) == expected_order


def parse_ordering(printer) -> str:
    output = []

    regex = re.compile(r'>> ([\w]+) <<')
    for entry in regex.findall(printer.message):
        if entry == 'ADDED':
            output.append('R')
        elif entry == 'REMOVED':
            output.append('L')

    return ''.join(output)


def test_file_no_longer_exists(printer, mock_user_decision):
    secretsA = SecretsCollection()
    secretsA['fileB'].add(potential_secret_factory('a'))

    secretsB = SecretsCollection()
    secretsB['fileA'].add(potential_secret_factory('a'))

    run_logic(secretsA, secretsB)
    assert not mock_user_decision.called


def test_fails_when_no_line_number(printer):
    secretsA = get_secrets(potential_secret_factory('a', line_number=0))
    secretsB = get_secrets(potential_secret_factory('b'))

    with allow_fake_files():
        run_logic(secretsA, secretsB)

    assert 'ERROR: No line numbers found' in printer.message


def run_logic(secretsA: SecretsCollection, secretsB: SecretsCollection):
    with mock_named_temporary_file() as f, mock_named_temporary_file() as g:
        baseline.save_to_file(secretsA, f.name)
        baseline.save_to_file(secretsB, g.name)

        main(['audit', '--diff', f.name, g.name])


def get_secrets(*secrets) -> SecretsCollection:
    output = SecretsCollection()
    for secret in secrets:
        output[secret.filename].add(secret)

    return output


@contextmanager
def allow_fake_files():
    with mock.patch(
        'detect_secrets.core.secrets_collection.os.path.exists',
        return_value=True,
    ), mock.patch(
        'detect_secrets.audit.compare.open_file',
    ), mock.patch(
        'detect_secrets.audit.compare.get_code_snippet',
    ), mock.patch(
        'detect_secrets.audit.compare.get_raw_secret_from_file',
        return_value='does not matter',
    ):
        yield


@pytest.fixture(autouse=True)
def mock_user_decision():
    # Always skip, to get to the end.
    with mock.patch(
        'detect_secrets.audit.compare.io.get_user_decision',
        return_value=InputOptions.SKIP,
    ) as m:
        yield m
