import pytest

from detect_secrets.plugins.openai import OpenAIDetector


class TestOpenAIDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # pragma: allowlist nextline secret
            ('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', True),
            # pragma: allowlist nextline secret
            ('sk-proj-Xi8tdMjHV6pmbBbwilTeT3BlbkFJ3UDnpdEwNNm6wVBpYM0o', True),
            # pragma: allowlist nextline secret
            ('sk-proj-Xi8tdMjHV6pmbBbwilTeT4BlbkFJ3UDnpdEwNNm6wVBpYM0o', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = OpenAIDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)

        assert len(output) == int(should_flag)
