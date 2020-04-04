import pytest

from detect_secrets.plugins.mailchimp import MailchimpDetector
from testing.mocks import mock_file_object


class TestMailchimpKeyDetector:

    @pytest.mark.parametrize(
        'file_content,should_flag',
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
    def test_analyze(self, file_content, should_flag):
        logic = MailchimpDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename
