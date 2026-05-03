import random
import string
import textwrap
from contextlib import contextmanager

import pytest

from detect_secrets.audit.report import SecretClassToPrint
from detect_secrets.audit.sarif import generate_sarif_report
from detect_secrets.audit.sarif import SARIF_VERSION
from detect_secrets.audit.sarif import TOOL_NAME
from detect_secrets.audit.sarif import TOOL_URI
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.settings import transient_settings
from testing.mocks import mock_named_temporary_file


url_format = 'http://username:{}@www.example.com/auth'
first_secret = 'value1'
random_secret = ''.join(random.choice(string.ascii_letters) for _ in range(8))
aws_secret = 'AKIAZZZZZZZZZZZZZZZZ'


def test_envelope_structure(baseline_file):
    """The top-level shape must satisfy SARIF 2.1.0 consumers (GH, GitLab)."""
    sarif = generate_sarif_report(baseline_file)

    assert sarif['version'] == SARIF_VERSION
    assert sarif['$schema'].endswith('sarif-schema-2.1.0.json')
    assert len(sarif['runs']) == 1

    driver = sarif['runs'][0]['tool']['driver']
    assert driver['name'] == TOOL_NAME
    assert driver['informationUri'] == TOOL_URI
    assert 'version' in driver
    assert 'semanticVersion' in driver

    # Every result must reference an existing rule by ruleId / ruleIndex.
    rules = driver['rules']
    rule_ids = {r['id'] for r in rules}
    for result in sarif['runs'][0]['results']:
        assert result['ruleId'] in rule_ids
        assert 0 <= result['ruleIndex'] < len(rules)


def test_results_contain_findings(baseline_file):
    sarif = generate_sarif_report(baseline_file)
    results = sarif['runs'][0]['results']
    # We added a real BasicAuth secret + a real AWS key + lines etc.
    assert len(results) > 0
    # Every result has a physical location with a uri + startLine.
    for result in results:
        assert result['locations'], 'every SARIF result must have at least one location'
        loc = result['locations'][0]['physicalLocation']
        assert 'uri' in loc['artifactLocation']
        assert loc['region']['startLine'] > 0
        assert 'snippet' in loc['region']
        # partialFingerprints make consumer dedupe stable across runs.
        assert 'detectSecretsHash/v1' in result['partialFingerprints']


def test_only_real_filter(baseline_file):
    """class_to_print=REAL_SECRET keeps real findings, drops VERIFIED_FALSE."""
    sarif = generate_sarif_report(baseline_file, SecretClassToPrint.REAL_SECRET)
    categories = {r['properties']['category'] for r in sarif['runs'][0]['results']}
    assert 'VERIFIED_FALSE' not in categories
    assert categories  # not empty


def test_only_false_filter(baseline_file):
    """class_to_print=FALSE_POSITIVE keeps only the audited false-positives."""
    sarif = generate_sarif_report(baseline_file, SecretClassToPrint.FALSE_POSITIVE)
    categories = {r['properties']['category'] for r in sarif['runs'][0]['results']}
    # Every result that survives must classify as a false-positive.
    for category in categories:
        from detect_secrets.constants import VerifiedResult
        assert SecretClassToPrint.from_class(VerifiedResult[category]) == \
            SecretClassToPrint.FALSE_POSITIVE


def test_kind_field_reflects_classification(baseline_file):
    """Per SARIF spec, 'kind' communicates triage state.

    True positives -> 'open' (action required), false-positives -> 'review'.
    """
    sarif = generate_sarif_report(baseline_file)
    for result in sarif['runs'][0]['results']:
        if result['properties']['category'] == 'VERIFIED_FALSE':
            assert result['kind'] == 'review'
        else:
            assert result['kind'] == 'open'


@contextmanager
def create_file_with_content(content):
    with mock_named_temporary_file() as f:
        f.write(content.encode())
        f.seek(0)
        yield f.name


@pytest.fixture
def baseline_file():
    first_content = textwrap.dedent(
        f"""
        url = {url_format.format(first_secret)}
        example = {url_format.format(random_secret)}
        link = {url_format.format(first_secret)}
    """,
    )[1:]
    second_content = textwrap.dedent(
        f"""
        url = {url_format.format(random_secret)}
    """,
    )[1:]
    third_content = textwrap.dedent(
        f"""
        aws_access_key = {aws_secret}
    """,
    )[1:]

    with create_file_with_content(first_content) as first_file, \
            create_file_with_content(second_content) as second_file, \
            create_file_with_content(third_content) as third_file, \
            mock_named_temporary_file() as baseline_file, \
            transient_settings({
                'plugins_used': [
                    {'name': 'BasicAuthDetector'},
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
            (second_file, BasicAuthDetector.secret_type, 1): False,
            (third_file, AWSKeyDetector.secret_type, 1): True,
        }
        for item in secrets:
            _, secret = item
            secret.is_secret = labels[(secret.filename, secret.type, secret.line_number)]
        baseline.save_to_file(secrets, baseline_file.name)
        baseline_file.seek(0)
        yield baseline_file.name
