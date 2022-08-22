import pytest

from detect_secrets.plugins.grafana import GrafanaDetector


class TestGrafanaDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('eyJrIjoiR0ZXZmt1UFc0OEpIOGN5RWdUalBJTllUTk83VlhtVGwiLCJuIjoiYXBpa2V5Y3VybCIsImlkIjo2'
            'fQ==', True),
            ('glsa_Q0tTx59W5f7LXgxiM4MjJs75176oun5F_e5c6b96d', True),
            ('eyJrIjoiZjJlZThiNDMwZGQ0ZDhjNjJhYmQwZWY3NDgxYzhjNjRiNzZkNjYyMiIsIm4iOiJ0ZXN0LWtleSIs'
            'ImlkIjo5OTk5OX0=', True),
            ('glc_eyJrIjoiZjI0YzZkNGEwZDBmZmZjMmUzNTU2ODcxMmY0ZWZlNTQ1NTljMDFjOCIsIm4iOiJteXRva2Vu'
            'IiwiaWQiOjF9', True),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = GrafanaDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
