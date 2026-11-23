import re

import pytest

from detect_secrets.util.prevalidation import could_match
from detect_secrets.util.prevalidation import required_literals


def literals(pattern: str):
    return required_literals(re.compile(pattern))


class TestRequiredLiterals:
    @staticmethod
    @pytest.mark.parametrize(
        'pattern, expected',
        [
            (r'xapp-\d-[A-Z0-9]+', {'xapp-'}),
            (r'AKIA[0-9A-Z]{16}', {'akia'}),
            (r'(?i)(?:atlassian|confluence|jira)\s*=\s*([a-z0-9]{24})', {'atlassian', 'confluence', 'jira'}),
            (r'-----BEGIN RSA PRIVATE KEY-----', {'-----begin rsa private key-----'}),
            (r'(?:token)+_[a-z]{10}', {'token'}),
            (r'password(?=\s*=)', {'password'}),
            (r'\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}\b', {'a3t', 'abia', 'acca', 'akia', 'asia'}),
        ],
    )
    def test_derives_required_literals(pattern, expected):
        assert literals(pattern) == frozenset(expected)

    @staticmethod
    def test_prefers_the_most_selective_literal():
        assert literals(r'key\s*=\s*sk_live_[a-z0-9]{24}') == frozenset({'sk_live_'})

    @staticmethod
    @pytest.mark.parametrize(
        'pattern',
        [
            r'[A-Za-z0-9]{40}',  # no literal at all
            r'(?:ab|cd)[0-9]{10}',  # literals shorter than the minimum length
            r'(?:secret)?[a-z0-9]{32}',  # optional literal is not required
            r'(?:secret|[0-9]{8})[a-z]{10}',  # one alternative has no literal
            r'(?!secret)[a-z]{10}',  # negative lookahead is not a requirement
        ],
    )
    def test_returns_none_when_no_requirement_is_provable(pattern):
        assert literals(pattern) is None

    @staticmethod
    def test_invalid_pattern_source_returns_none():
        from detect_secrets.util.prevalidation import required_literals_for_source
        assert required_literals_for_source('(unclosed') is None


class TestCouldMatch:
    @staticmethod
    def test_none_requirement_always_matches():
        assert could_match(None, 'anything')

    @staticmethod
    def test_matching_is_case_insensitive_on_lowered_documents():
        requirement = literals(r'AKIA[0-9A-Z]{16}')
        assert could_match(requirement, 'aws_key = "akiaabcdefghijklmnop"')

    @staticmethod
    def test_document_without_any_literal_cannot_match():
        requirement = literals(r'(?i)(?:atlassian|jira)\s*=\s*([a-z0-9]{24})')
        assert not could_match(requirement, 'def add(a, b):\n    return a + b\n')

    @staticmethod
    @pytest.mark.parametrize(
        'pattern, document',
        [
            (r'(?i)(?:atlassian|confluence|jira)\s*=\s*([a-z0-9]{24})', 'JIRA = a1b2c3d4e5f6g7h8i9j0k1l2'),
            (r'AKIA[0-9A-Z]{16}', 'id = AKIAABCDEFGHIJKLMNOP'),
            (r'xapp-\d-[A-Z0-9]+', 'token: xapp-1-ABC123'),
        ],
    )
    def test_never_skips_a_document_that_the_pattern_matches(pattern, document):
        assert re.search(pattern, document)
        assert could_match(literals(pattern), document.lower())
