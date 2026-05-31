import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector


class TestGitHubTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('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', True),
            ('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', True),  # noqa: E501
            ('github_pat_' + 'a' * 50, False),
            ('foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', False),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GitHubTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
