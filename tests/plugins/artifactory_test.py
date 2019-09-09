import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.artifactory import ArtifactoryDetector


ARTIFACTORY_TOKEN = 'AKCxxxxxxxxxx'
ARTIFACTORY_TOKEN_BYTES = b'AKCxxxxxxxxxx'


class TestArtifactoryDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('AP6xxxxxxxxxx', True),
            ('AP2xxxxxxxxxx', True),
            ('AP3xxxxxxxxxx', True),
            ('AP5xxxxxxxxxx', True),
            ('APAxxxxxxxxxx', True),
            ('APBxxxxxxxxxx', True),
            ('AKCxxxxxxxxxx', True),
            (' AP6xxxxxxxxxx', True),
            (' AKCxxxxxxxxxx', True),
            ('=AP6xxxxxxxxxx', True),
            ('=AKCxxxxxxxxxx', True),
            ('\"AP6xxxxxxxxxx\"', True),
            ('\"AKCxxxxxxxxxx\"', True),
            ('artif-key:AP6xxxxxxxxxx', True),
            ('artif-key:AKCxxxxxxxxxx', True),
            ('X-JFrog-Art-Api: AKCxxxxxxxxxx', True),
            ('X-JFrog-Art-Api: AP6xxxxxxxxxx', True),
            ('artifactoryx:_password=AKCxxxxxxxxxx', True),
            ('artifactoryx:_password=AP6xxxxxxxxxx', True),
            ('testAKCwithinsomeirrelevantstring', False),
            ('testAP6withinsomeirrelevantstring', False),
            ('X-JFrog-Art-Api: $API_KEY', False),
            ('X-JFrog-Art-Api: $PASSWORD', False),
            ('artifactory:_password=AP6xxxxxx', False),
            ('artifactory:_password=AKCxxxxxxxx', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = ArtifactoryDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=401,
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
    def test_verify_status_not_200_or_401(self):
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

    @responses.activate
    def test_verify_valid_secret_bytes(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=200,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_status_not_200_or_401_bytes(self):
        responses.add(
            responses.GET, 'https://%s/api/system/ping' % ArtifactoryDetector().artifactory_url,
            status=500,
        )
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN_BYTES) == VerifiedResult.UNVERIFIED

    @responses.activate
    def test_verify_unverified_secret(self):
        assert ArtifactoryDetector().verify(ARTIFACTORY_TOKEN) == VerifiedResult.UNVERIFIED
