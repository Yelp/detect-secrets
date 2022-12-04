import pytest

from detect_secrets.plugins.discord import DiscordBotTokenDetector


class TestDiscordBotTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # From https://discord.com/developers/docs/reference#authentication
            (
                'MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs',
                True,
            ),
            (
                'Nzk5MjgxNDk0NDc2NDU1OTg3.YABS5g.2lmzECVlZv3vv6miVnUaKPQi2wI',
                True,
            ),
            # From https://docs.gitguardian.com/secrets-detection/detectors/specifics/discord_bot_token#examples  # noqa: E501
            (
                'MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC',
                True,
            ),
            # Random values to fail
            (
                'MZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zMC',
                False,
            ),
            (
                'SZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zMC',
                False,
            ),
            (
                'MZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zM',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = DiscordBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == (1 if should_flag else 0)
