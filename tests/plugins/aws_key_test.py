from __future__ import absolute_import
from __future__ import unicode_literals

import pytest

from detect_secrets.plugins.aws import AWSKeyDetector
from testing.mocks import mock_file_object


class TestAWSKeyDetector(object):

    @pytest.mark.parametrize(
        'file_content,should_flag',
        [
            (
                'AKIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'akiazzzzzzzzzzzzzzzz',
                False,
            ),
            (
                'AKIAZZZ',
                False,
            ),
        ],
    )
    def test_analyze(self, file_content, should_flag):
        logic = AWSKeyDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
