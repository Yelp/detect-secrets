import pytest

from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector


class TestAzureStorageKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'AccountKey=lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',  # noqa: E501
                True,
            ),
            (
                'AccountKey="lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ=="',  # noqa: E501
                True,
            ),
            (
                "AccountKey='lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ=='",  # noqa: E501
                True,
            ),
            (
                'lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',  # noqa: E501
                True,
            ),
            (
                'learS3Bucket',
                False,
            ),
            (
                'anupRole',
                False,
            ),
            (
                'cret',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AzureStorageKeyDetector()
        assert bool(logic.analyze_line(filename='mock_filename', line=payload)) == should_flag
