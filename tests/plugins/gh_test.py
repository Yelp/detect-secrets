from __future__ import absolute_import

import pytest

from detect_secrets.plugins.gh import GHDetector


class TestGHDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('2764d47e6bf540911b7da8fe55caa9451e783549', True),  # not real key
            ('key :53d49d5081266d939bac57a3d86c517ded974b19', True),  # not real key
            ('53d49dnotakeyata9bac57a3d86c517ded974b19', False),  # has non-hex
            ('a654fd9e3758a65235c765cf51e10df0c80b7a9', False),  # only 39
            ('a654fd9e3758a65235c765cf51e10df0c80b7a923', False),  # 41
            ('2764d47e6bf540911b7da8fe55caa9451e783549 ', True),  # not real key
            ('2764d47e6bf540911b7da8fe55caa9451e7835492 ', False),  # not real key
            ('2764d47e6bf540911b7da8fe55caa9451e783549_ ', False),  # not real key
            ('2764d47e6bf540911b7da8fe55caa9451e783549z ', False),  # not real key
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = GHDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
