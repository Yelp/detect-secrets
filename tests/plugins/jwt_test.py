from __future__ import absolute_import

import pytest

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.jwt import JwtTokenDetector


class TestJwtTokenDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', True),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', True),  # noqa: E501
            ('{"alg":"HS256","typ":"JWT"}.{"name":"Jon Doe"}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            ('bm90X3ZhbGlkX2pzb25fYXRfYWxs.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', False),  # noqa: E501
            ('test', False),  # noqa: E501
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = JwtTokenDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, result',
        [
            ('yJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.UNVERIFIED),  # noqa: E501
            (u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.UNVERIFIED),  # noqa: E501
            ('eyJhbasdGciOiJIUaddasdasfsasdasdzI1NiIasdsInR5cCI6IkpXVCasdJasd9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', VerifiedResult.UNVERIFIED),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVC.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJAAAA.eyJBBB', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJBB.eyJCC.eyJDDDD', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
            ('eyJasdasdraWQiOadfssdmgkandjgnjidfnsgiIyMDE5MDUxMyIsImFsZyI6IlasdJTMjU2Iasdnasd0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfasdQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', VerifiedResult.VERIFIED_FALSE),  # noqa: E501
        ],
    )
    def test_verify(self, payload, result):
        logic = JwtTokenDetector()
        output = logic.verify(payload)

        assert output == result
