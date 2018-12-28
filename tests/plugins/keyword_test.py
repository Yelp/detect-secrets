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
            "'theapikey': 'ho)pe]nob(ody[finds>-_$#thisone'",
            '"theapikey": "ho)pe]nob(ody[finds>-_$#thisone"',
            'apikey: ho)pe]nob(ody[finds>-_$#thisone',
            'apikey:ho)pe]nob(ody[finds>-_$#thisone',
            'theapikey:ho)pe]nob(ody[finds>-_$#thisone',
            'apikey: "ho)pe]nob(ody[finds>-_$#thisone"',
            "apikey:  'ho)pe]nob(ody[finds>-_$#thisone'",
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            'some_dict["secret"] = "ho)pe]nob(ody[finds>-_$#thisone"',
            "some_dict['secret'] = ho)pe]nob(ody[finds>-_$#thisone",
            'my_password=ho)pe]nob(ody[finds>-_$#thisone',
            'my_password= ho)pe]nob(ody[finds>-_$#thisone',
            'my_password =ho)pe]nob(ody[finds>-_$#thisone',
            'my_password = ho)pe]nob(ody[finds>-_$#thisone',
            'my_password =ho)pe]nob(ody[finds>-_$#thisone',
            'the_password=ho)pe]nob(ody[finds>-_$#thisone\n',
            'the_password= "ho)pe]nob(ody[finds>-_$#thisone"\n',
            'the_password=\'ho)pe]nob(ody[finds>-_$#thisone\'\n',
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            'apikey "ho)pe]nob(ody[finds>-_$#thisone";',  # Double-quotes
            'fooapikeyfoo "ho)pe]nob(ody[finds>-_$#thisone";',  # Double-quotes
            'fooapikeyfoo"ho)pe]nob(ody[finds>-_$#thisone";',  # Double-quotes
            'private_key \'ho)pe]nob(ody[finds>-_$#thisone\';',  # Single-quotes
            'fooprivate_keyfoo\'ho)pe]nob(ody[finds>-_$#thisone\';',  # Single-quotes
            'fooprivate_key\'ho)pe]nob(ody[finds>-_$#thisone\';',  # Single-quotes
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
                == PotentialSecret.hash_secret('ho)pe]nob(ody[finds>-_$#thisone')
            )

    @pytest.mark.parametrize(
        'file_content',
        [
            # FOLLOWED_BY_COLON_QUOTES_REQUIRED_RE
            "'theapikey': 'hope]nobody[finds>-_$#thisone'",
            '"theapikey": "hope]nobody[finds>-_$#thisone"',
            'apikey: "hope]nobody[finds>-_$#thisone"',
            "apikey:  'hope]nobody[finds>-_$#thisone'",
            # FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE
            'some_dict["secret"] = "hope]nobody[finds>-_$#thisone"',
            'the_password= "hope]nobody[finds>-_$#thisone"\n',
            'the_password=\'hope]nobody[finds>-_$#thisone\'\n',
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            'apikey "hope]nobody[finds>-_$#thisone";',  # Double-quotes
            'fooapikeyfoo "hope]nobody[finds>-_$#thisone";',  # Double-quotes
            'fooapikeyfoo"hope]nobody[finds>-_$#thisone";',  # Double-quotes
            'private_key \'hope]nobody[finds>-_$#thisone\';',  # Single-quotes
            'fooprivate_keyfoo\'hope]nobody[finds>-_$#thisone\';',  # Single-quotes
            'fooprivate_key\'hope]nobody[finds>-_$#thisone\';',  # Single-quotes
        ],
    )
    def test_analyze_python_positives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.py')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename.py' == potential_secret.filename
            assert (
                potential_secret.secret_hash
                == PotentialSecret.hash_secret('hope]nobody[finds>-_$#thisone')
            )

    @pytest.mark.parametrize(
        'file_content',
        [
            # FOLLOWED_BY_COLON_RE
            'private_key "";',  # Nothing in the quotes
            'private_key \'"no spaces\';',  # Has whitespace in the secret
            'private_key "fake";',  # 'fake' in the secret
            'private_key "hopenobodyfindsthisone\';',  # Double-quote does not match single-quote
            'private_key \'hopenobodyfindsthisone";',  # Single-quote does not match double-quote
            # FOLLOWED_BY_QUOTES_AND_SEMICOLON_RE
            'theapikey: ""',  # Nothing in the quotes
            'theapikey: "somefakekey"',  # 'fake' in the secret
            'theapikeyforfoo:hopenobodyfindsthisone',  # Characters between apikey and :
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            'some_key = "real_secret"',  # We cannot make 'key' a Keyword, too noisy
            'my_password = foo(hey)you',  # Has a ( followed by a )
            "my_password = request.json_body['hey']",  # Has a [ followed by a ]
            'my_password = ""',  # Nothing in the quotes
            "my_password = ''",  # Nothing in the quotes
            'my_password = True',  # 'True' is a known false-positive
            'my_password = "fakesecret"',  # 'fake' in the secret
            'login(username=username, password=password)',  # secret is password)
            'open(self, password = ""):',  # secrets is ""):
            # '',
        ],
    )
    def test_analyze_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename.foo')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'secret_starting_with_dollar_sign',
        [
            # FOLLOWED_BY_EQUAL_SIGNS_RE
            '$password = $input;',
        ],
    )
    def test_analyze_php_negatives(self, secret_starting_with_dollar_sign):
        logic = KeywordDetector()

        f = mock_file_object(secret_starting_with_dollar_sign)
        output = logic.analyze(f, 'mock_filename.php')
        assert len(output) == 0

    @pytest.mark.parametrize(
        'secret_with_no_quote',
        [
            # FOLLOWED_BY_COLON_QUOTES_REQUIRED_RE
            'apikey: hope]nobody[finds>-_$#thisone',
            'apikey:hope]nobody[finds>-_$#thisone',
            'theapikey:hope]nobody[finds>-_$#thisone',
            # FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED_RE
            "some_dict['secret'] = hope]nobody[finds>-_$#thisone",
            'my_password=hope]nobody[finds>-_$#thisone',
            'my_password= hope]nobody[finds>-_$#thisone',
            'my_password =hope]nobody[finds>-_$#thisone',
            'my_password = hope]nobody[finds>-_$#thisone',
            'my_password =hope]nobody[finds>-_$#thisone',
            'the_password=hope]nobody[finds>-_$#thisone\n',
        ],
    )
    def test_analyze_python_negatives(self, secret_with_no_quote):
        logic = KeywordDetector()

        f = mock_file_object(secret_with_no_quote)
        output = logic.analyze(f, 'mock_filename.py')
        assert len(output) == 0
