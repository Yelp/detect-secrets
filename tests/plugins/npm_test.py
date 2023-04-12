import pytest

from detect_secrets.plugins.npm import NpmDetector


class TestNpmDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e', True),
            ('//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx', True),
            ('//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('foo', False),
            ('//registry.npmjs.org/:_authToken=${NPM_TOKEN}', False),
            ('//gitlab.com/api/v4/projects/1347/packages/npm/:_authToken=glpat-a8r3xUFrtP-isd1DLK_r', True),
            ('//gitlab.com/api/v4/projects/1347/packages/npm/:_authToken=${CI_JOB_TOKEN}', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = NpmDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
