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
            # From https://github.com/Yelp/detect-secrets/issues/627
            (
                'OTUyNED5MDk2MTMxNzc2MkEz.YjESug.UNf-1GhsIG8zWT409q2C7Bh_zWQ',
                True,
            ),
            (
                'OTUyNED5MDk2MTMxNzc2MkEz.GSroKE.g2MTwve8OnUAAByz8KV_ZTV1Ipzg4o_NmQWUMs',
                True,
            ),
            (
                'MTAyOTQ4MTN5OTU5MTDwMEcxNg.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8',
                True,
            ),
            # Pass - token starts on the 3rd character (first segment is 24 characters)
            (
                'ATMyOTQ4MTN5OTU5MTDwMEcxNg.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8',
                True,
            ),
            # Pass - token starts on the 2nd character (first segment is 25 characters)
            (
                '=MTAyOTQ4MTN5OTU5MTDwMEcxN.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8',
                True,
            ),
            # Pass - token ends before the '!' (last segment is 27 characters)
            (
                'MTAyOTQ4MTN5OTU5MTDwMEcxNg.YjESug.UNf-1GhsIG8zWT409q2C7Bh_zWQ!4o_NmQWUMs',
                True,
            ),
            # Fail - all segments too short (23.5.26)
            (
                'MZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zMC',
                False,
            ),
            # Fail - first segment too short (23.6.27)
            (
                'MZ1yGvKTj0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC',
                False,
            ),
            # Fail - middle segment too short (24.5.27)
            (
                'MZ1yGvKTjE0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC',
                False,
            ),
            # Fail - last segment too short (24.6.26)
            (
                'MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zM',
                False,
            ),
            # Fail - contains invalid character ','
            (
                'MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe,4iUcrGOuegj57zMC',
                False,
            ),
            # Fail - invalid first character 'P' (must be one of M/N/O)
            (
                'PZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC',
                False,
            ),
            # Fail - first segment 1 character too long; causes invalid first character 'T'
            (
                'MTAyOTQ4MTN5OTU5MTDwMEcxNg0.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = DiscordBotTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == (1 if should_flag else 0)
