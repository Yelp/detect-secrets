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
                'login_somewhere --http-password hopenobodyfindsthisone\n'
            ),
            (
                'token = "noentropy"'
            ),
        ],
    )
    def test_analyze(self, file_content):
        logic = KeywordDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == 1
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
