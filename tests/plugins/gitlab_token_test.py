import pytest

from detect_secrets.plugins.gitlab_token import GitLabTokenDetector


class TestGitLabTokenDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                # valid PAT prefix and token length
                'glpat-hellOworld380_testin',
                True,
            ),
            (
                # spaces are not part of the token
                'glpat-hellOWorld380 testin',
                False,
            ),
            (
                # invalid separator (underscore VS dash)
                'glpat_hellOworld380_testin',
                False,
            ),
            (
                # valid different prefix and token length
                'gldt-HwllOuhfw-wu0rlD_yep',
                True,
            ),
            (
                # token < 20 chars should be too short
                'gldt-seems_too000Sshorty',
                False,
            ),
            (
                # invalid prefix, but valid token length
                'foo_hello-world80_testin',
                False,
            ),
            (
                # token length may vary depending on the impl., but <= 50 chars should be fine
                'glsoat-PREfix_helloworld380_testin_pretty_long_token_long',
                True,
            ),
            (
                # token > 50 chars is too long
                'glsoat-PREfix_helloworld380_testin_pretty_long_token_long_',
                False,
            ),
            (
                # GitLab is not GitHub
                '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',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
