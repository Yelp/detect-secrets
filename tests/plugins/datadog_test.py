import pytest
import responses

from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.datadog import DatadogDetector


class TestDatadogDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # API keys (32 hex chars)
            ('DD_API_KEY=abcdef0123456789abcdef0123456789', True),
            ('dd_api_key = "abcdef0123456789abcdef0123456789"', True),
            ('DATADOG_API_KEY=abcdef0123456789abcdef0123456789', True),
            ('datadog_api_key: abcdef0123456789abcdef0123456789', True),
            # App keys (40 hex chars)
            ('DD_APP_KEY=abcdef0123456789abcdef0123456789abcdef01', True),
            ('DATADOG_APP_KEY=abcdef0123456789abcdef0123456789abcdef01', True),
            ('datadog_application_key: abcdef0123456789abcdef0123456789abcdef01', True),
            # False positives
            ('DD_API_KEY=abcdef012345', False),  # too short
            ('random_variable=abcdef0123456789abcdef0123456789', False),  # no datadog context
            ('DD_API_KEY=ghijklmnopqrstuv0123456789abcdef', False),  # non-hex chars
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = DatadogDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.GET,
            'https://api.datadoghq.com/api/v1/validate',
            json={'valid': True},
            status=200,
        )

        assert (
            DatadogDetector().verify('abcdef0123456789abcdef0123456789')
            == VerifiedResult.VERIFIED_TRUE
        )

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.GET,
            'https://api.datadoghq.com/api/v1/validate',
            json={'errors': ['Forbidden']},
            status=403,
        )

        assert (
            DatadogDetector().verify('abcdef0123456789abcdef0123456789')
            == VerifiedResult.VERIFIED_FALSE
        )
