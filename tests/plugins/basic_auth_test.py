from __future__ import absolute_import

import pytest

from detect_secrets.plugins.basic_auth import BasicAuthDetector


class TestBasicAuthDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('https://username:password@yelp.com', True,),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = BasicAuthDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
