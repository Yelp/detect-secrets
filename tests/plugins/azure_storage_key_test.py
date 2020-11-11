import pytest

from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector


class AzureStorageKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'AccountKey=lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                True,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AzureStorageKeyDetector()
        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert output
