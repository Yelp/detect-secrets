import pytest
import responses

from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.nuntiq import checksum
from detect_secrets.plugins.nuntiq import NuntiqDetector


# Format-valid credentials with a correct checksum that were never issued: they cannot
# authenticate anywhere.
CUSTOMER_KEY = (
    # pragma: allowlist nextline secret
    'nuntiq_ck_live_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C'
)
PARTNER_KEY = (
    # pragma: allowlist nextline secret
    'nuntiq_pk_live_326e932b_pcvLCgsshxMD84d2YyG8mqrkXIcXBG0-YhknB7Q6zDU3ggTr8'
)
ROTATION_SECRET = (
    # pragma: allowlist nextline secret
    'nuntiq_rs_live_21de8760_SqPffdMtVohhIsr6xV3cb9KQeXZ33W2DY2jtbXBeY0Q2ESzMW'
)
TEST_ENV_KEY = (
    # pragma: allowlist nextline secret
    'nuntiq_ck_test_e8bcfd3f_IwlPImwzSnmfIZ7hFLDQea4xhIznzZvKRPzBU5D0WSQ457xL8'
)
DEV_ENV_KEY = CUSTOMER_KEY.replace('_live_', '_dev_')


class TestNuntiqDetector:

    @pytest.mark.parametrize(
        'key',
        [CUSTOMER_KEY, PARTNER_KEY, ROTATION_SECRET, TEST_ENV_KEY],
    )
    def test_checksum(self, key):
        assert checksum(key[-49:-6]) == key[-6:]

    @pytest.mark.parametrize(
        'payload, expected',
        [
            ('NUNTIQ_API_KEY=' + CUSTOMER_KEY, [CUSTOMER_KEY]),
            ('{"X-API-Key": "' + PARTNER_KEY + '"}', [PARTNER_KEY]),
            ('rotation_secret: ' + ROTATION_SECRET, [ROTATION_SECRET]),
            (
                'curl -H "X-API-Key: ' + TEST_ENV_KEY + '" https://test-api.apreceiving.com/',
                [TEST_ENV_KEY],
            ),
            ('key = "' + DEV_ENV_KEY + '"', [DEV_ENV_KEY]),
            # Keys next to each other
            (CUSTOMER_KEY + ',' + PARTNER_KEY, [CUSTOMER_KEY, PARTNER_KEY]),
            # Wrong checksum
            ('NUNTIQ_API_KEY=' + CUSTOMER_KEY[:-1] + 'D', []),
            # Part of a longer token
            ('NUNTIQ_API_KEY=' + CUSTOMER_KEY + 'x', []),
            ('x' + CUSTOMER_KEY, []),
            # Display form of a key
            ('key: nuntiq_ck_live_1a2b3c4d...wXyZ', []),
            # Unknown kind or environment
            (CUSTOMER_KEY.replace('nuntiq_ck_', 'nuntiq_xk_'), []),
            (CUSTOMER_KEY.replace('_live_', '_prod_'), []),
            # Key id is lowercase hex
            (CUSTOMER_KEY.replace('1787e770', '1787E770'), []),
        ],
    )
    def test_analyze(self, payload, expected):
        logic = NuntiqDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert sorted(secret.secret_value for secret in output) == sorted(expected)

    @pytest.mark.parametrize(
        'key, host',
        [
            (CUSTOMER_KEY, 'api.apreceiving.com'),
            (TEST_ENV_KEY, 'test-api.apreceiving.com'),
            (DEV_ENV_KEY, 'dev-api.apreceiving.com'),
        ],
    )
    @responses.activate
    def test_verify_valid_secret(self, key, host):
        responses.add(
            responses.POST, 'https://{}/api/v1/key-check'.format(host),
            json={'valid': True, 'kind': 'customer_api_key', 'environment': key.split('_')[2]},
            status=200,
        )

        assert NuntiqDetector().verify(key) == VerifiedResult.VERIFIED_TRUE
        assert responses.calls[0].request.headers['X-API-Key'] == key

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.POST, 'https://api.apreceiving.com/api/v1/key-check',
            json={'valid': False, 'kind': None, 'environment': None},
            status=200,
        )

        assert NuntiqDetector().verify(CUSTOMER_KEY) == VerifiedResult.VERIFIED_FALSE

    @pytest.mark.parametrize(
        'status, body',
        [
            (429, '{"valid": false}'),
            (503, 'Service Unavailable'),
            (200, 'not json'),
            (200, '[]'),
            (200, '{"kind": null}'),
            (200, '{"valid": "true"}'),
        ],
    )
    @responses.activate
    def test_verify_unexpected_answer(self, status, body):
        responses.add(
            responses.POST, 'https://api.apreceiving.com/api/v1/key-check',
            body=body,
            status=status,
        )

        assert NuntiqDetector().verify(CUSTOMER_KEY) == VerifiedResult.UNVERIFIED
