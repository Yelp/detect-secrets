import pytest

from detect_secrets.plugins.pypi_token import PypiTokenDetector


class TestPypiTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                # pragma: allowlist nextline secret
                'pypi-AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRkLTM0MjNiNmEwNWIzYgACF1sxLFsitesttestbWluaW1hbC1wcm9qZWN0Il1dAAIsWzIsWyJjYWY4OTAwZi0xNDMwLTRiYQstYmFmMi1mMDE3OGIyNWZhNTkiXV0AAAYgh2UINPjWBDwT0r3tQ1o5oZyswcjN0-IluP6z34SX3KM', True,  # noqa: E501
            ),
            (
                # pragma: allowlist nextline secret
                'pypi-AgENdGVzdC5weXBpLm9yZwIkN2YxOWZhOWEtY2FjYS00MGZhLTj2MGEtODFjMnE2MjdmMzY0AAIqWzMsImJlM2FiOWI5LTRmYUTnNEg4ZS04Mjk0LWFlY2Y2NWYzNGYzNyJdAAAGIMb5Hb8nVvhcAizcVVzA-bKKnwN7Pe0RmgPRCvrPwyJf', True,  # noqa: E501
            ),
            (
                # pragma: allowlist nextline secret
                'pypi-AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRkLTM0MjNiNmEwNWIzYgACF1sxLFsibWluaW1h', False,  # noqa: E501
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = PypiTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)
