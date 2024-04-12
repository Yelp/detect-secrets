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
                'foo-hello-world80_testin',
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
    def test_base_token_format(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('GR1348941PREfix_helloworld380', True),
            ('GR1348941PREfix_helloworld380_testin_pretty_long_token_long', True),
            ('GR1348941PREfix_helloworld380_testin_pretty_long_token_long_', False),  # too long
            ('GR1348941helloWord0', False),  # too short
        ],
    )
    def test_runner_registration_token(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('glcbt-helloworld380_testin', True),
        ],
    )
    def test_cicd_token(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('glimt-my-tokens_are-correctAB38', True),
            ('glimt-my-tokens_are-correctAB', False),  # too short
            ('glimt-my-tokens_are-correctAB38_280', False),  # too long
        ],
    )
    def test_incoming_mail_token(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('glptt-Need5_T00-be-exactly-40-chars--ELse_fail', True),
            ('glptt-Need5_T00-be-exactly-40-chars--ELse_failing', False),  # too long
            ('glptt-hellOworld380_testin', False),  # too short
        ],
    )
    def test_trigger_token(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('glagent-Need5_T00-bee-longer-than-50_chars-or-else-failING', True),
            ('glagent-Need5_T00-bee-longer-than-50_chars-or-else-failING-still_OK', True),
            (('glagent-' + 'X' * 1025), False),  # 2 long
            ('glagent-hellOworld380_testin', False),  # len 20 is too short
        ],
    )
    def test_agent_token(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('gloas-checking_Length-Is-_exactly_64--checking_Length-Is-_exactly_64--', True),
            ('gloas-checking_Length-Is-checking_Length-Is-', False),  # too short
            ('gloas-checking_Length-Is-_exactly_64--Xchecking_Length-Is-_longer_longer', False),
        ],
    )
    def test_oauth_application_secret(self, payload, should_flag):
        logic = GitLabTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
