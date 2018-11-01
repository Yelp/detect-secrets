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
                "'theapikey': 'hopenobodyfinds>-_$#thisone'"
            ),
            (
                '"theapikey": "hopenobodyfinds>-_$#thisone"'
            ),
            (
                'apikey: hopenobodyfinds>-_$#thisone'
            ),
            (
                'apikey:hopenobodyfinds>-_$#thisone'
            ),
            (
                'theapikey:hopenobodyfinds>-_$#thisone'
            ),
            (
                'apikey: "hopenobodyfinds>-_$#thisone"'
            ),
            (
                "apikey:  'hopenobodyfinds>-_$#thisone'"
            ),
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            (
                'my_password=hopenobodyfinds>-_$#thisone'
            ),
            (
                'my_password= hopenobodyfinds>-_$#thisone'
            ),
            (
                'my_password =hopenobodyfinds>-_$#thisone'
            ),
            (
                'my_password_for_stuff = hopenobodyfinds>-_$#thisone'
            ),
            (
                'my_password_for_stuff =hopenobodyfinds>-_$#thisone'
            ),
            (
                'passwordone=hopenobodyfinds>-_$#thisone\n'
            ),
            (
                'passwordone= "hopenobodyfinds>-_$#thisone"\n'
            ),
            (
                'passwordone=\'hopenobodyfinds>-_$#thisone\'\n'
            ),
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            (
                'apikey "hopenobodyfinds>-_$#thisone";'  # Double-quotes
            ),
            (
                'fooapikeyfoo "hopenobodyfinds>-_$#thisone";'  # Double-quotes
            ),
            (
                'fooapikeyfoo"hopenobodyfinds>-_$#thisone";'  # Double-quotes
            ),
            (
                'private_key \'hopenobodyfinds>-_$#thisone\';'  # Single-quotes
            ),
            (
                'fooprivate_keyfoo\'hopenobodyfinds>-_$#thisone\';'  # Single-quotes
            ),
            (
                'fooprivate_key\'hopenobodyfinds>-_$#thisone\';'  # Single-quotes
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
                == PotentialSecret.hash_secret('hopenobodyfinds>-_$#thisone')
            )

    @pytest.mark.parametrize(
        'file_content',
        [
            # FOLLOWED_BY_COLON_RE
            (
                'private_key "";'  # Nothing in the quotes
            ),
            (
                'private_key \'"no spaces\';'  # Has whitespace in the secret
            ),
            (
                'private_key "fake";'  # 'fake' in the secret
            ),
            (
                'private_key "hopenobodyfindsthisone\';'  # Double-quote does not match single-quote
            ),
            (
                'private_key \'hopenobodyfindsthisone";'  # Single-quote does not match double-quote
            ),
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            (
                'theapikey: ""'  # Nothing in the quotes
            ),
            (
                'theapikey: "somefakekey"'  # 'fake' in the secret
            ),
            (
                'theapikeyforfoo:hopenobodyfindsthisone'  # Characters between apikey and :
            ),
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            (
                'some_key = "real_secret"'  # We cannot make 'key' a Keyword, too noisy
            ),
            (
                'my_password_for_stuff = ""'  # Nothing in the quotes
            ),
            (
                "my_password_for_stuff = ''"  # Nothing in the quotes
            ),
            (
                'my_password_for_stuff = True'  # 'True' is a known false-positive
            ),
            (
                'my_password_for_stuff = "fakesecret"'  # 'fake' in the secret
            ),
        ],
    )
    def test_analyze_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 0
