import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.artifactory import ArtifactoryDetector


ARTIFACTORY_TOKEN = 'AKCxxxxxxxxxx'
ARTIFACTORY_TOKEN_BYTES = b'AKCxxxxxxxxxx'


class TestArtifactoryDetector(object):

    @pytest.mark.parametrize(
        'token, payload, should_flag',
        [
            ('AP6xxxxxxxxxx', 'AP6xxxxxxxxxx', True),
            ('AP2xxxxxxxxxx', 'AP2xxxxxxxxxx', True),
            ('AP3xxxxxxxxxx', 'AP3xxxxxxxxxx', True),
            ('AP5xxxxxxxxxx', 'AP5xxxxxxxxxx', True),
            ('APAxxxxxxxxxx', 'APAxxxxxxxxxx', True),
            ('APBxxxxxxxxxx', 'APBxxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', 'AKCxxxxxxxxxx', True),
            ('AP6xxxxxxxxxx', ' AP6xxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', ' AKCxxxxxxxxxx', True),
            ('AP6xxxxxxxxxx', '=AP6xxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', '=AKCxxxxxxxxxx', True),
            ('AP6xxxxxxxxxx', '\"AP6xxxxxxxxxx\"', True),
            ('AKCxxxxxxxxxx', '\"AKCxxxxxxxxxx\"', True),
            ('AP6xxxxxxxxxx', 'artif-key:AP6xxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', 'artif-key:AKCxxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', 'X-JFrog-Art-Api: AKCxxxxxxxxxx', True),
            ('AP6xxxxxxxxxx', 'X-JFrog-Art-Api: AP6xxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', 'artifactoryx:_password=AKCxxxxxxxxxx', True),
            ('AP6xxxxxxxxxx', 'artifactoryx:_password=AP6xxxxxxxxxx', True),
            ('', 'testAKCwithinsomeirrelevantstring', False),
            ('', 'testAP6withinsomeirrelevantstring', False),
            ('', 'X-JFrog-Art-Api: $API_KEY', False),
            ('', 'X-JFrog-Art-Api: $PASSWORD', False),
            ('', 'artifactory:_password=AP6xxxxxx', False),
            ('', 'artifactory:_password=AKCxxxxxxxx', False),
        ],
    )
    def test_analyze_string(self, token, payload, should_flag):
        logic = ArtifactoryDetector()

        output = logic.analyze_string(payload, 1, 'mock_filename', output_raw=True)
        assert len(output) == int(should_flag)
        if len(output) > 0:
            assert list(output.keys())[0].secret == token

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=401,
        )

        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.VERIFIED_FALSE

        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=403,
        )

        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=200,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_401_403(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=500,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_invalid_secret_bytes(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=401,
        )

        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == \
            VerifiedResult.VERIFIED_FALSE

        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=403,
        )

        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == \
            VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret_bytes(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=200,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_401_403_bytes(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=500,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_unverified_secret(self):
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.UNVERIFIED
