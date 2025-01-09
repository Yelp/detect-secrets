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
            # no azure mention
            (
                """
                nomention.com +WITH IDENTITY = 'IDENTITY'
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                """,
                False,
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
            # azure lowercase
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                azure.com +WITH IDENTITY = 'IDENTITY',
                """,
                True,
            ),
            # azure uppercase
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                AZURE.com +WITH IDENTITY = 'IDENTITY'""",
                True,
            ),
            # azure capitalize
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                Azure.com +WITH IDENTITY = 'IDENTITY'
                """,
                True,
            ),
            # no azure mention
            (
                """
                lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ==
                nomention.com +WITH IDENTITY = 'IDENTITY'
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
            (
                """
                resolution: {integrity: sha512-/AazAV/F+HK4LIywF9C+NYHcJo038zEnWkteilcxC1FM/uK/4NVGDKGrxx7nNq1ybspAroRKT4I1FHfxQzxkUw==}
                engines: {node: '>=12.0.0'}
                peerDependencies:
                    '@azure/identity': '*'
                    '@azure/msal-browser': '*'
                    buffer: '*'
                    stream-browserify: '*'
                """,
                False,
            ),
            (
                    """
                    "Microsoft.AspNetCore.AzureAppServices.HostingStartup/2.0.1": {
                        "sha512": "hdneJMBdHdrlMc/NYaNS8GFWlR/3tN7TsV/jOSBuc61+gWULwu45t+I7g5IF/iCHWI9PLMLNP5VOj+d1Tv1zUA=="
                    }
                    """,
                    False,
            ),
            (
                    """
                    "Microsoft.AspNetCore.AzureAppServicesIntegration/2.0.1": {
                        "sha512": "r2JMiK8RB2mHGKWIc+NVViT++2ZxCAGJBbLtptINB32F/c3DrNEtKWVNs2MEldEb822llBjrRmsJ7cScCW+P7g=="
                    }
                    """,
                    False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = AzureStorageKeyDetector()
        assert bool(logic.analyze_line(filename='mock_filename', line=payload)) == should_flag
