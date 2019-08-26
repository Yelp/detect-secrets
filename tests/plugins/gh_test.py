from __future__ import absolute_import

import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.gh import GHDetector

GHE_TOKEN = 'abcdef0123456789abcdef0123456789abcdef01'


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

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=401,
        )

        assert GHDetector().verify(GHE_TOKEN) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=200,
        )
        assert GHDetector().verify(GHE_TOKEN) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_or_401(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=500,
        )
        assert GHDetector().verify(GHE_TOKEN) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_unverified_secret(self):
        assert GHDetector().verify(GHE_TOKEN) == VerifiedResult.UNVERIFIED
