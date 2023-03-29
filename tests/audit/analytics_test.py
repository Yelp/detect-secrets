import json
import random
import string
from contextlib import contextmanager

import pytest

from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from testing.factories import potential_secret_factory as original_potential_secret_factory
from testing.mocks import mock_named_temporary_file


def potential_secret_factory(**kwargs):
    return original_potential_secret_factory(
        # We just need a legitimate type, it doesn't matter what.
        type=BasicAuthDetector.secret_type,

        # Create a random value for the secret, so they are not the same secret.
        secret=''.join(random.choice(string.ascii_letters) for _ in range(8)),
        **kwargs,
    )


def test_basic_statistics_json(printer):
    with labelled_secrets() as filename:
        main(['audit', filename, '--stats', '--json'])

    data = json.loads(printer.message)
    assert data == {
        'BasicAuthDetector': {
            'stats': {
                'raw': {
                    'true-positives': 1,
                    'false-positives': 2,
                    'unknown': 1,
                },
                'score': {
                    'precision': 0.3333,
                    'recall': 0.5,
                },
            },
        },
    }


@pytest.mark.parametrize(
    'secret',
    (
        # This should cause a `precision` float division error.
        potential_secret_factory(),

        # While rarer, this should cause a `recall` float division error
        potential_secret_factory(is_secret=False),
    ),
)
def test_no_divide_by_zero(secret):
    secrets = SecretsCollection()
    secrets['file'].add(secret)
    with mock_named_temporary_file() as f:
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        main(['audit', f.name, '--stats', '--json'])


def test_basic_statistics_str(printer):
    with labelled_secrets() as filename:
        main(['audit', filename, '--stats'])

    assert printer.message == (
        'Plugin: BasicAuthDetector\nStatistics: True Positives: 1, ' +
        'False Positives: 2, Unknown: 1, Precision: 0.3333, Recall: 0.5\n\n\n'
    )


@contextmanager
def labelled_secrets():
    # Create our own SecretsCollection manually, so that we have fine-tuned control.
    secrets = SecretsCollection()
    secrets['fileA'] = {
        potential_secret_factory(),
        potential_secret_factory(is_secret=True),
        potential_secret_factory(is_secret=False),
    }
    secrets['fileB'] = {
        potential_secret_factory(is_secret=False),
    }

    with mock_named_temporary_file() as f:
        baseline.save_to_file(secrets, f.name)
        f.seek(0)

        yield f.name
