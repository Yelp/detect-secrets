import pytest

from detect_secrets.plugins.artifactory import ArtifactoryDetector


class TestArtifactoryDetector:

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
            ('not_artifactory_password=AAAAxxxxxxx:APA91xxxxx', False),  # firebase messaging api
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = ArtifactoryDetector()

        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
