import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.github_enterprise import GheDetector

GHE_TOKEN_OLD = 'abcdef0123456789abcdef0123456789abcdef01'
TOKEN_STRING = 'wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx'
GHE_TOKEN_NEW = 'ghp_'+TOKEN_STRING
GHE_TOKEN_BYTES = b'abcdef0123456789abcdef0123456789abcdef01'

class TestGheDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # Old GitHub Enterprise token format
            ('github-key 2764d47e6bf540911b7da8fe55caa9451e783549', True),
            ('github_pwd :53d49d5081266d939bac57a3d86c517ded974b19', True),
            ('gh-api-key=2764d47e6bf540911b7da8fe55caa9451e783549 ', True),
            ('git-token => "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('git_token => "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('git-pat="abcdef0123456789abcdef0123456789abcdef01"', True),
            ('ghe_pat = "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('ghe = "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('auth_token :=\'abcdef0123456789abcdef0123456789abcdef01\'', True),
            ('secret => abcdef0123456789abcdef0123456789abcdef01', True),
            ('credential :abcdef0123456789abcdef0123456789abcdef01', True),
            ('pasword :abcdef0123456789abcdef0123456789abcdef01', True),
            ('gh_pw := abcdef0123456789abcdef0123456789abcdef01', True),
            ('auth_api-key = abcdef0123456789abcdef0123456789abcdef01', True),
            ('"GHE_API_KEY": "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('GITHUB_API_TOKEN := "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('https://username:abcdef0123456789abcdef0123456789abcdef01@github.ibm.com', True),
            (
                'https://username:abcdef0123456789abcdef0123456789abcdef01@'
                'api.github.ibm.com', True,
            ),
            ('Authorization: token abcdef0123456789abcdef0123456789abcdef01', True),
            (
                'Authorization: Basic '
                'YWJjZWRmYWJlZmQzMzMzMTQ1OTA4YWJjZGRmY2JkZGUxMTQ1Njc4OQo=', True,
            ),
            ('password abcdef0123456789abcdef0123456789abcdef01', True),
            ('cred = abcdef0123456789abcdef0123456789abcdef01', True),
            ('auth = abcdef0123456789abcdef0123456789abcdef01', True),
            ('gh-credentials: abcdef0123456789abcdef0123456789abcdef01', True),
            ('git+https://abcdef0123456789abcdef0123456789abcdef01@github.ibm.com', True),
            ('sonar.github.oauth=abcdef0123456789abcdef0123456789abcdef01', True),
            (
                'https://x-oauth-basic:abcdef0123456789abcdef0123456789abcdef01'
                '@github.ibm.com/org/repo.git', True,
            ),
            ('abcdef0123456789abcdef0123456789abcdef01', False),  # no keyword prefix
            ('gh-token=53d49dnotakeyata9bac57a3d86c517ded974b19', False),  # has non-hex
            ('GIT-KEY: a654fd9e3758a65235c765cf51e10df0c80b7a9', False),  # only 39
            ('github_api_key: a654fd9e3758a65235c765cf51e10df0c80b7a923', False),  # 41
            ('gh_key:=2764d47e6bf540911b7da8fe55caa9451e7835492 ', False),
            ('github-api-token: 2764d47e6bf540911b7da8fe55caa9451e783549_ ', False),
            ('git_key=2764d47e6bf540911b7da8fe55caa9451e783549z ', False),
            ('https://<fake-username>:<fake-pass>@github.ibm.com', False),
            (
                'Authorization: llama '
                'YWJjZWRmYWJlZmQzMzMzMTQ1OTA4YWJjZGRmY2JkZGUxMTQ1Njc4OQo=', False,
            ),
            ('Authorization: token %s', False),
            # New GitHub token format
            (GHE_TOKEN_NEW, True),
            ('gho_'+TOKEN_STRING, True),
            ('ghu_'+TOKEN_STRING, True),
            ('ghs_'+TOKEN_STRING, True),
            ('ghr_'+TOKEN_STRING, True),
            ('new_ghe_token: abcdef0123456789abcdef0123456789abcdef01', False), # missing prefix
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = GheDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'https://username:'+GHE_TOKEN_OLD+'@github.somecompany.com', True,
            ),
            (
                'https://username:'+GHE_TOKEN_OLD+'@api.github.somecompany.com', True,
            ),
            (   'git+https://'+GHE_TOKEN_OLD+'@github.somecompany.com', True),
            (
                'https://x-oauth-basic:'+GHE_TOKEN_OLD+'@github.somecompany.com/org/repo.git', True,
            ),
            (
                'https://username:'+GHE_TOKEN_NEW+'@github.somecompany.com', True,
            ),
            (
                'https://username:'+GHE_TOKEN_NEW+'@api.github.somecompany.com', True,
            ),
            (   'git+https://'+GHE_TOKEN_NEW+'@github.somecompany.com', True),
            (
                'https://x-oauth-basic:'+GHE_TOKEN_NEW+'@github.somecompany.com/org/repo.git', True,
            ),
        ],
    )
    def test_analyze_line_non_(self, payload, should_flag):
        logic = GheDetector('github.somecompany.com')

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=401,
        )

        assert GheDetector().verify(GHE_TOKEN_OLD) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=200,
        )
        assert GheDetector().verify(GHE_TOKEN_OLD) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_or_401(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=500,
        )
        assert GheDetector().verify(GHE_TOKEN_OLD) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_invalid_secret_bytes(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=401,
        )

        assert GheDetector().verify(GHE_TOKEN_BYTES) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret_bytes(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=200,
        )
        assert GheDetector().verify(GHE_TOKEN_BYTES) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_or_401_bytes(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=500,
        )
        assert GheDetector().verify(GHE_TOKEN_BYTES) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_unverified_secret(self):
        assert GheDetector().verify(GHE_TOKEN_OLD) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_invalid_secret_new(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=401,
        )

        assert GheDetector().verify(GHE_TOKEN_NEW) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_status_not_200_or_401_new(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=500,
        )
        assert GheDetector().verify(GHE_TOKEN_NEW) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_valid_secret_new(self):
        responses.add(
            responses.GET, 'https://github.ibm.com/api/v3', status=200,
        )
        assert GheDetector().verify(GHE_TOKEN_NEW) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_unverified_secret_new(self):
        assert GheDetector().verify(GHE_TOKEN_NEW) == VerifiedResult.UNVERIFIED