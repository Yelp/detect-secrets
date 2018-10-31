from __future__ import absolute_import
from __future__ import unicode_literals

import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.keyword import KeywordDetector
from testing.mocks import mock_file_object


class TestKeywordDetector(object):

    @pytest.mark.parametrize(
        'file_content',
        [
            # FOLLOWED_BY_COLON_RE
            (
                'apikey: hopenobodyfindsthisone'
            ),
            (
                'apikey:hopenobodyfindsthisone'
            ),
            (
                'theapikey:hopenobodyfindsthisone'
            ),
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            (
                'my_password=hopenobodyfindsthisone'
            ),
            (
                'my_password= hopenobodyfindsthisone'
            ),
            (
                'my_password =hopenobodyfindsthisone'
            ),
            (
                'my_password_for_stuff = hopenobodyfindsthisone'
            ),
            (
                'my_password_for_stuff =hopenobodyfindsthisone'
            ),
            (
                'passwordone=hopenobodyfindsthisone\n'
            ),
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            (
                'apikey "hopenobodyfindsthisone";'  # Double-quotes
            ),
            (
                'fooapikeyfoo "hopenobodyfindsthisone";'  # Double-quotes
            ),
            (
                'fooapikeyfoo"hopenobodyfindsthisone";'  # Double-quotes
            ),
            (
                'private_key \'hopenobodyfindsthisone\';'  # Single-quotes
            ),
            (
                'fooprivate_keyfoo\'hopenobodyfindsthisone\';'  # Single-quotes
            ),
            (
                'fooprivate_key\'hopenobodyfindsthisone\';'  # Single-quotes
            ),
        ],
    )
    def test_analyze_positives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
            assert (
                potential_secret.secret_hash
                == PotentialSecret.hash_secret('hopenobodyfindsthisone')
            )

    @pytest.mark.parametrize(
        'file_content',
        [
            # FOLLOWED_BY_COLON_RE
            (
                'private_key \'"no spaces\';'  # Has whitespace in-between
            ),
            (
                'private_key "hopenobodyfindsthisone\';'  # Double-quote does not match single-quote
            ),
            (
                'private_key \'hopenobodyfindsthisone";'  # Single-quote does not match double-quote
            ),
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            (
                'theapikeyforfoo:hopenobodyfindsthisone'  # Characters between apikey and :
            ),
        ],
    )
    def test_analyze_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 0
