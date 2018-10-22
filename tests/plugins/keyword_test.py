from __future__ import absolute_import
from __future__ import unicode_literals

import pytest

from detect_secrets.plugins.keyword import KeywordDetector
from testing.mocks import mock_file_object


class TestKeywordDetector(object):

    @pytest.mark.parametrize(
        'file_content',
        [
            (
                'apikey "something";'
            ),
            (
                'token "something";'
            ),
            (
                'private_key \'"something\';'  # Single-quotes not double-quotes
            ),
            (
                'apikey:'
            ),
            (
                'the_token:'
            ),
            (
                'my_password ='
            ),
            (
                'some_token_for_something ='
            ),
            (
                '  pwd = foo'
            ),
            (
                'private_key "something";'
            ),

            (
                'passwordone=foo\n'
            ),
            (
                'API_KEY=hopenobodyfindsthisone\n'
            ),
            (
                'token = "noentropy"'
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

    @pytest.mark.parametrize(
        'file_content',
        [
            (
                'private_key \'"no spaces\';'  # Has whitespace in-between
            ),
            (
                'passwordonefoo\n'  # No = or anything
            ),
            (
                'api_keyhopenobodyfindsthisone:\n'  # Has char's in between api_key and :
            ),
            (
                'my_pwd ='  # Does not start with pwd
            ),
            (
                'token "noentropy;'  # No 2nd double-quote
            ),
            (
                'token noentropy;'  # No quotes
            ),
        ],
    )
    def test_analyze_negatives(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 0
