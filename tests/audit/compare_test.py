import re
import socket
import ssl
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


def occurrence_factory(
    secret: str,
    filename: str = 'a.py',
    line_number: int = 1,
    type: str = 'Basic Auth',
):
    """Builds a `PotentialSecret` with its real hash, at a specific location.

    NOTE: `SecretsCollection` deduplicates on (filename, type, secret_hash), so two
    entries at different lines need different plugin types to be retained.
    """
    return original_potential_secret_factory(
        type=type,
        filename=filename,
        secret=secret,
        line_number=line_number,
    )


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
    'secretsA, secretsB, expected_output',
    (
        # A matching secret must not swallow an added secret in the next file.
        (
            [occurrence_factory('dummy-value', filename='a.py')],
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='b.py'),
            ],
            [('ADDED', 'b.py')],
        ),
        # ... nor a removed secret in the next file.
        (
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='b.py'),
            ],
            [occurrence_factory('dummy-value', filename='a.py')],
            [('REMOVED', 'b.py')],
        ),
        # Multiple file boundaries, all sharing the same secret value.
        (
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='c.py'),
            ],
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='b.py'),
                occurrence_factory('dummy-value', filename='c.py'),
            ],
            [('ADDED', 'b.py')],
        ),
        # A matched secret must not consume the leftovers of an exhausted baseline.
        (
            [
                occurrence_factory('dummy-value'),
                occurrence_factory('dummy-value', line_number=2, type='Private Key'),
            ],
            [occurrence_factory('dummy-value')],
            [('REMOVED', 'a.py')],
        ),
        (
            [occurrence_factory('dummy-value')],
            [
                occurrence_factory('dummy-value'),
                occurrence_factory('dummy-value', line_number=2, type='Private Key'),
            ],
            [('ADDED', 'a.py')],
        ),
        # Same location, same value, different plugins: deliberately collapsed.
        (
            [
                occurrence_factory('dummy-value'),
                occurrence_factory('dummy-value', type='Private Key'),
            ],
            [occurrence_factory('dummy-value')],
            [],
        ),
        # Different hashes are actual changes; ordered by hash of the shared location.
        (
            [occurrence_factory('dummy-old')],
            [occurrence_factory('dummy-new')],
            [('REMOVED', 'a.py'), ('ADDED', 'a.py')],
        ),
        # Equal baselines, and empty baselines, stay silent.
        (
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='b.py'),
            ],
            [
                occurrence_factory('dummy-value', filename='a.py'),
                occurrence_factory('dummy-value', filename='b.py'),
            ],
            [],
        ),
        ([], [], []),
    ),
)
def test_occurrence_boundaries(printer, secretsA, secretsB, expected_output):
    with allow_fake_files():
        run_logic(get_secrets(*secretsA), get_secrets(*secretsB))

    assert parse_audit_output(printer.message) == expected_output


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


def parse_audit_output(message: str):
    """Returns the rendered (status, filename) entries, in display order."""
    output = []
    filename = None

    # Strip ANSI escape codes, since colorization depends on the terminal.
    message = re.sub(r'\x1b\[[0-9;]*m', '', message)
    for line in message.splitlines():
        match = re.search(r'Filename:\s+(\S+)', line)
        if match:
            filename = match.group(1)
            continue

        match = re.search(r'>> (ADDED|REMOVED) <<', line)
        if match:
            output.append((match.group(1), filename))

    return output


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


def deny_network(*args, **kwargs):
    raise AssertionError('audit comparison tests must not use the network')


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Guards this offline test module against accidental socket usage.

    `ssl` is imported at module load time, so patching the bound methods of the
    existing socket classes is enough -- including for `ssl.SSLSocket` subclasses.
    """
    monkeypatch.setattr(socket.socket, 'connect', deny_network)
    monkeypatch.setattr(socket.socket, 'connect_ex', deny_network)
    monkeypatch.setattr(ssl.SSLSocket, 'connect', deny_network)
    monkeypatch.setattr(ssl.SSLSocket, 'connect_ex', deny_network)
    monkeypatch.setattr(socket, 'create_connection', deny_network)
