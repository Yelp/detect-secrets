import pytest

from detect_secrets.plugins.jwt import JwtTokenDetector


class TestJwtTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # valid jwt
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', True),  # noqa: E501
            # valid jwt - but header contains CR/LF-s
            ('eyJ0eXAiOiJKV1QiLA0KImFsZyI6IkhTMjU2In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', True),  # noqa: E501
            # valid jwt - but claims contain bunch of LF newlines
            ('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9lIiwKInN0YXR1cyI6ImVtcGxveWVlIgp9', True),  # noqa: E501
            # valid jwt - claims contain strings with unicode accents
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IsWww6HFkcOtIMOWxZHDqcOoIiwiaWF0IjoxNTE2MjM5MDIyfQ.k5HibI_uLn_RTuPcaCNkaVaQH2y5q6GvJg8GPpGMRwQ', True),  # noqa: E501
            # as unicode literal
            (u'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', True),  # noqa: E501
            # no signature - but still valid
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ', True),  # noqa: E501
            # decoded - invalid
            ('{"alg":"HS256","typ":"JWT"}.{"name":"Jon Doe"}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            # invalid json - invalid (caught by regex)
            ('bm90X3ZhbGlkX2pzb25fYXRfYWxs.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            # missing claims - invalid
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', False),  # noqa: E501
            # totally not a jwt
            ('jwt', False),  # noqa: E501
            # invalid json with random bytes
            ('eyJhbasdGciOiJIUaddasdasfsasdasdzI1NiIasdsInR5cCI6IkpXVCasdJasd9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            # invalid json in jwt header - invalid (caught by parsing)
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', False),  # noqa: E501
            # good by regex, but otherwise totally not JWT
            ('eyJAAAA.eyJBBB', False),  # noqa: E501
            ('eyJBB.eyJCC.eyJDDDD', False),  # noqa: E501
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = JwtTokenDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
