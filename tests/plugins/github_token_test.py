import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector


class TestGitHubTokenDetector:

    @pytest.mark.parametrize(
        'payload, expected_secret',
        [
            ('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', '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'),
            ('ghs_12345_eyJhbGciOiJSUzI1NiJ9.' + 'A'*100 + '.' + 'B'*100, 'ghs_12345_eyJhbGciOiJSUzI1NiJ9.' + 'A'*100 + '.' + 'B'*100),
            ('ghs_12345_eyJhbGciOiJSUzI1NiJ9.' + 'A'*300 + '.' + 'B'*300, 'ghs_12345_eyJhbGciOiJSUzI1NiJ9.' + 'A'*300 + '.' + 'B'*300),
            ('foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', None),
            ('foo', None),
        ],
    )
    def test_analyze(self, payload, expected_secret):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        
        if expected_secret:
            assert len(output) == 1
            assert next(iter(output)).secret_value == expected_secret
        else:
            assert len(output) == 0
