import pytest

from detect_secrets.plugins.npm import NpmDetector


class TestNpmDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('//registry.npmjs.org/:_authToken=xxxxxxxxxxxxxxxxxxxx', True),
            ('//registry.npmjs.org:_authToken=xxxxxxxxxxxxxxxxxxxx', False),
            ('registry.npmjs.org/:_authToken=xxxxxxxxxxxxxxxxxxxx', False),
            ('///:_authToken=xxxxxxxxxxxxxxxxxxxx', False),
            ('_authToken=xxxxxxxxxxxxxxxxxxxx', False),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = NpmDetector()
        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
