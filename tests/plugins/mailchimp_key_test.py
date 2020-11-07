import pytest

from detect_secrets.plugins.mailchimp import MailchimpDetector


class TestMailchimpKeyDetector:

    @pytest.mark.parametrize(
        'line,should_flag',
        [
            (
                '343ea45721923ed956e2b38c31db76aa-us30',
                True,
            ),
            (
                'a2937653ed38c31a43ea46e2b19257db-us2',
                True,
            ),
            (
                '3ea4572956e2b381923ed34c31db76aa-2',
                False,
            ),
            (
                'aea462953eb192d38c31a433e76257db-al32',
                False,
            ),
            (
                '9276a43e2951aa46e2b1c33ED38357DB-us2',
                False,
            ),
            (
                '3a5633e829d3c71-us2',
                False,
            ),
        ],
    )
    def test_analyze(self, line, should_flag):
        logic = MailchimpDetector()

        output = logic.analyze_line(filename='mock_filename', line=line)
        assert len(output) == (1 if should_flag else 0)
