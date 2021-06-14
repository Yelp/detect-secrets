import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector


class TestGitHubTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('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', True),
            ('foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', False),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
