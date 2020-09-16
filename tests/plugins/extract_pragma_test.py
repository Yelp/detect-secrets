import pytest

from detect_secrets.plugins.base import BasePlugin


class TestExtractPragma:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('public static final String my_by_pass_new = \"12edcf0a5f420e97b1418afb29c71f729f8608dd\"; // pragma: allowlist secrets', True),  # noqa: E501
            ('public static final String secret_bypass_new = \"mytestpass12345dd\"; // pragma: allowlist secrets', True),  # noqa: E501
            ('public static final String test = env.Var;', False),
            ('public static final String new_test = env.Var;', False),
        ],
    )
    def test_analyze_pragma_line(self, payload, should_flag):
        base = BasePlugin()

        output = base.analyze_pragma_line(payload, 1)
        assert len(output) >= int(should_flag)
