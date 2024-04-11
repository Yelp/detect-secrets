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
                False,
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

            # Test skip only public keys
            (
                'PublicKey: lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                False,
            ),
            (
                'PublicKey: ssh-rsa lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                False,
            ),
            (
                'SshPublicKey: ssh-rsa lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                False,
            ),
            (
                'PublicKeys: lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                False,
            ),
            (
                'SshPublicKeys: lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                False,
            ),
            (
                '(https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = \'IDENTITY\', lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==',
                True,
            ),

            # Test multilines

            # azure is mentioned within the 1 line above
            (
                """(https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY',
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure is mentioned within the 2 lines above
            (
                """(https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY',
                some data here
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure is mentioned within the 2 lines above
            (
                """(https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY',

                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure is mentioned within the 3 lines above
            (
                """(https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY',
                some data 1
                some data 2
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                False,
            ),
            # azure lowercase
            (
                """azure.com +WITH IDENTITY = 'IDENTITY',
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure uppercase
            (
                """AZURE.com +WITH IDENTITY = 'IDENTITY',
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure capitalize
            (
                """Azure.com +WITH IDENTITY = 'IDENTITY',
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                True,
            ),
            # azure is mentioned within the 1 line below
            (
                """lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                (https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY'
                """,
                True,
            ),
            # azure is mentioned within the 2 lines below
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                some data 1
                (https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY'
                """,
                True,
            ),
            # azure is mentioned within the 3 lines below
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                some data 1
                some data 2
                (https://portal.azure.com/). +CREATE DATABASE SCOPED CREDENTIAL AzureStorageCredential +WITH IDENTITY = 'IDENTITY'
                """,
                False,
            ),
            (
                """SshPublicKeys:
                - lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                False,
            ),
            (
                """SshPublicKeys:
                - >-
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==""",
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AzureStorageKeyDetector()
        assert bool(logic.analyze_line(filename='mock_filename', line=payload)) == should_flag
