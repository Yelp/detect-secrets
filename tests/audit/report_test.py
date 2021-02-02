import os
import random
import string
import tempfile

import pytest

from detect_secrets.audit.report import generate_report
from detect_secrets.audit.report import SecretClassToPrint
from detect_secrets.constants import VerifiedResult
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.jwt import JwtTokenDetector
from testing.factories import potential_secret_factory as original_potential_secret_factory


CREATED_FILES = []


@pytest.mark.parametrize(
    'class_to_print, expected_real, expected_false',
    [
        (None, 2, 2),
        (SecretClassToPrint.REAL_SECRET, 2, 0),
        (SecretClassToPrint.FALSE_POSITIVE, 0, 3),
    ],
)
def test_generate_report(class_to_print, expected_real, expected_false):
    filename = baseline_file()
    output = generate_report(filename, class_to_print)
    real, false = count_results(output)
    assert real == expected_real
    assert false == expected_false
    delete_all_temporal_files()


def count_results(data):
    real_secrets = 0
    false_secrets = 0
    for secret in data:
        if SecretClassToPrint.from_class(VerifiedResult[secret['category']]) == SecretClassToPrint.REAL_SECRET:  # noqa: E501
            real_secrets += 1
        else:
            false_secrets += 1
    return real_secrets, false_secrets


def baseline_file():
    # Create our own SecretsCollection manually, so that we have fine-tuned control.
    url_format = 'http://username:{}@www.example.com/auth'
    first_secret = 'value1'
    second_secret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'  # noqa: E501
    random_secret = ''.join(random.choice(string.ascii_letters) for _ in range(8))
    file_content = 'url = ' + url_format.format(first_secret) \
        + '\nexample = ' + url_format.format(random_secret) \
        + '\nlink = ' + url_format.format(first_secret)
    first_file = create_file_with_content(file_content)
    file_content = 'url = ' + url_format.format(second_secret) \
        + '\nexample = ' + url_format.format(random_secret)
    second_file = create_file_with_content(file_content)
    secrets = SecretsCollection()
    secrets[first_file] = {
        original_potential_secret_factory(
            type=BasicAuthDetector.secret_type,
            secret=first_secret,
            is_secret=True,
            line_number=1,
            filename=first_file,
        ),
        original_potential_secret_factory(
            type=BasicAuthDetector.secret_type,
            secret=random_secret,
            is_secret=False,
            line_number=2,
            filename=first_file,
        ),
        original_potential_secret_factory(
            type=BasicAuthDetector.secret_type,
            secret=first_secret,
            is_secret=True,
            line_number=3,
            filename=first_file,
        ),
    }
    secrets[second_file] = {
        original_potential_secret_factory(
            type=JwtTokenDetector.secret_type,
            secret=second_secret,
            is_secret=True,
            line_number=1,
            filename=second_file,
        ),
        original_potential_secret_factory(
            type=BasicAuthDetector.secret_type,
            secret=second_secret,
            is_secret=False,
            line_number=1,
            filename=second_file,
        ),
        original_potential_secret_factory(
            type=BasicAuthDetector.secret_type,
            secret=random_secret,
            is_secret=False,
            line_number=2,
            filename=second_file,
        ),
    }

    f = tempfile.NamedTemporaryFile(delete=False)
    baseline.save_to_file(secrets, f.name)
    f.seek(0)
    CREATED_FILES.append(f.name)
    return f.name


def create_file_with_content(file_content):
    f = tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', delete=False)
    f.write(file_content)
    f.seek(0)
    CREATED_FILES.append(f.name)
    return f.name


def delete_all_temporal_files():
    for file in CREATED_FILES:
        if os.path.exists(file):
            os.remove(file)
