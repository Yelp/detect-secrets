import random
import string
import textwrap
from contextlib import contextmanager

import pytest

from detect_secrets.audit.report import generate_report
from detect_secrets.audit.report import SecretClassToPrint
from detect_secrets.constants import VerifiedResult
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.jwt import JwtTokenDetector
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


url_format = 'http://username:{}@www.example.com/auth'
first_secret = 'value1'
second_secret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'  # noqa: E501
random_secret = ''.join(random.choice(string.ascii_letters) for _ in range(8))
aws_secret = 'AKIAZZZZZZZZZZZZZZZZ'


@pytest.mark.parametrize(
    'class_to_print, expected_real, expected_false, expected_output',
    [
        (
            None, 4, 1,
            {
                'results': [
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'url = {}'.format(url_format.format(first_secret)),
                            3: 'link = {}'.format(url_format.format(first_secret)),
                        },
                        'secrets': first_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'UNVERIFIED',
                        'lines': {
                            2: 'example = {}'.format(url_format.format(random_secret)),
                        },
                        'secrets': random_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'url = {}'.format(url_format.format(second_secret)),
                        },
                        'secrets': second_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                            JwtTokenDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_FALSE',
                        'lines': {
                            2: 'example = {}'.format(url_format.format(random_secret)),
                        },
                        'secrets': random_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'aws_access_key = {}'.format(aws_secret),
                        },
                        'secrets': aws_secret,
                        'types': [
                            AWSKeyDetector.secret_type,
                        ],
                    },
                ],
            },
        ),
        (
            SecretClassToPrint.REAL_SECRET, 4, 0,
            {
                'results': [
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'url = {}'.format(url_format.format(first_secret)),
                            3: 'link = {}'.format(url_format.format(first_secret)),
                        },
                        'secrets': first_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'UNVERIFIED',
                        'lines': {
                            2: 'example = {}'.format(url_format.format(random_secret)),
                        },
                        'secrets': random_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'url = {}'.format(url_format.format(second_secret)),
                        },
                        'secrets': second_secret,
                        'types': [
                            JwtTokenDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_TRUE',
                        'lines': {
                            1: 'aws_access_key = {}'.format(aws_secret),
                        },
                        'secrets': aws_secret,
                        'types': [
                            AWSKeyDetector.secret_type,
                        ],
                    },
                ],
            },
        ),
        (
            SecretClassToPrint.FALSE_POSITIVE, 0, 2,
            {
                'results': [
                    {
                        'category': 'VERIFIED_FALSE',
                        'lines': {
                            1: 'url = {}'.format(url_format.format(second_secret)),
                        },
                        'secrets': second_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                    {
                        'category': 'VERIFIED_FALSE',
                        'lines': {
                            2: 'example = {}'.format(url_format.format(random_secret)),
                        },
                        'secrets': random_secret,
                        'types': [
                            BasicAuthDetector.secret_type,
                        ],
                    },
                ],
            },
        ),
    ],
)
def test_generate_report(
    class_to_print,
    expected_real,
    expected_false,
    expected_output,
    baseline_file,
):
    output = generate_report(baseline_file, class_to_print)
    real, false = count_results(output)
    assert real == expected_real
    assert false == expected_false
    for expected in expected_output['results']:
        found = False
        for item in output['results']:
            if expected['secrets'] == item['secrets'] and expected['category'] == item['category']:
                for key in expected.keys():
                    assert item[key] == expected[key]
                found = True
        assert found


def count_results(data):
    real_secrets = 0
    false_secrets = 0
    for secret in data['results']:
        if SecretClassToPrint.from_class(VerifiedResult[secret['category']]) == SecretClassToPrint.REAL_SECRET:  # noqa: E501
            real_secrets += 1
        else:
            false_secrets += 1
    return real_secrets, false_secrets


@contextmanager
def create_file_with_content(content):
    with mock_named_temporary_file() as f:
        f.write(content.encode())
        f.seek(0)
        yield f.name


@pytest.fixture
def baseline_file():
    # Create our own SecretsCollection manually, so that we have fine-tuned control.
    first_content = textwrap.dedent(f"""
        url = {url_format.format(first_secret)}
        example = {url_format.format(random_secret)}
        link = {url_format.format(first_secret)}
    """)[1:]
    second_content = textwrap.dedent(f"""
        url = {url_format.format(second_secret)}
        example = {url_format.format(random_secret)}
    """)[1:]
    third_content = textwrap.dedent(f"""
        aws_access_key = {aws_secret}
    """)[1:]

    with create_file_with_content(first_content) as first_file, \
            create_file_with_content(second_content) as second_file, \
            create_file_with_content(third_content) as third_file, \
            mock_named_temporary_file() as baseline_file, \
            transient_settings({
                'plugins_used': [
                    {'name': 'BasicAuthDetector'},
                    {'name': 'JwtTokenDetector'},
                    {'name': 'AWSKeyDetector'},

                ],
                'filters_used': [
                    {
                        'path':
                            'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
                        'min_level': 2,
                    },
                ],
            }):
        secrets = SecretsCollection()
        secrets.scan_file(first_file)
        secrets.scan_file(second_file)
        secrets.scan_file(third_file)
        labels = {
            (first_file, BasicAuthDetector.secret_type, 1): True,
            (first_file, BasicAuthDetector.secret_type, 2): None,
            (first_file, BasicAuthDetector.secret_type, 3): True,
            (second_file, JwtTokenDetector.secret_type, 1): True,
            (second_file, BasicAuthDetector.secret_type, 1): False,
            (second_file, BasicAuthDetector.secret_type, 2): False,
            (third_file, AWSKeyDetector.secret_type, 1): True,
        }
        for item in secrets:
            _, secret = item
            secret.is_secret = labels[(secret.filename, secret.type, secret.line_number)]
        baseline.save_to_file(secrets, baseline_file.name)
        baseline_file.seek(0)
        yield baseline_file.name
