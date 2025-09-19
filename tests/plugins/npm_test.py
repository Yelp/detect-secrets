import pytest

from detect_secrets.plugins.npm import NpmDetector


class TestNpmDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # Original UUID format _authToken tests
            ('//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e', True),
            ('//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx', True),
            
            # New _auth base64 tests
            ('//registry.npmjs.org/:_auth=dGVzdDp0ZXN0', True),
            ('//private.registry.com/:_auth=YWRtaW46cGFzc3dvcmQ=', True),
            ('//registry.example.com/:_auth=foobar', True),
            ('//registry.npmjs.org/:_auth= dGVzdDp0ZXN0', True),
            ('//registry.npmjs.org/:_auth=SGVsbG8gV29ybGQ+', True),
            
            # New arbitrary _authToken format tests
            ('//registry2.example.com/:_authToken=MYTOKEN2', True),
            ('//private.npm.registry/:_authToken=CUSTOM_TOKEN_123', True),
            ('//registry.npmjs.org/:_authToken=abc123def456', True),
            ('//registry.npmjs.org/:_authToken=token_with_underscores', True),
            ('//registry.npmjs.org/:_authToken=token-with-hyphens', True),
            ('//registry.npmjs.org/:_authToken= MYTOKEN2', True),
            
            # Negative tests - should not flag
            ('//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('_auth=dGVzdDp0ZXN0', False),
            ('foo', False),
            ('//registry.npmjs.org/:_authToken=${NPM_TOKEN}', False),
            ('//registry.npmjs.org/:_auth=${AUTH_TOKEN}', False),
            ('//registry.npmjs.org/:_authToken=', False),
            ('//registry.npmjs.org/:_auth=', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = NpmDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
