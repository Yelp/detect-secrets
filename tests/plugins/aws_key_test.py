import textwrap

import mock
import pytest

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import get_secret_access_key
from detect_secrets.plugins.aws import verify_aws_secret_access_key
from testing.mocks import mock_file_object


EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


class TestAWSKeyDetector:

    def setup(self):
        self.example_key = 'AKIAZZZZZZZZZZZZZZZZ'

    @pytest.mark.parametrize(
        'file_content,should_flag',
        [
            (
                'AKIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'akiazzzzzzzzzzzzzzzz',
                False,
            ),
            (
                'AKIAZZZ',
                False,
            ),
        ],
    )
    def test_analyze(self, file_content, should_flag):
        logic = AWSKeyDetector()

        f = mock_file_object(file_content)
        output = logic.analyze(f, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
        for potential_secret in output:
            assert 'mock_filename' == potential_secret.filename

    def test_verify_no_secret(self):
        logic = AWSKeyDetector()

        assert logic.verify(self.example_key, '') == VerifiedResult.UNVERIFIED

    def test_verify_valid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=True,
        ) as mock_verify:
            potential_secret = PotentialSecret('test aws', 'test filename', self.example_key)
            assert AWSKeyDetector().verify(
                self.example_key,
                '={}'.format(EXAMPLE_SECRET),
                potential_secret,
            ) == VerifiedResult.VERIFIED_TRUE
        assert potential_secret.other_factors['secret_access_key'] == EXAMPLE_SECRET
        mock_verify.assert_called_with(self.example_key, EXAMPLE_SECRET)

    def test_verify_invalid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=False,
        ) as mock_verify:
            potential_secret = PotentialSecret('test aws', 'test filename', self.example_key)
            assert AWSKeyDetector().verify(
                self.example_key,
                '={}'.format(EXAMPLE_SECRET),
                potential_secret,
            ) == VerifiedResult.VERIFIED_FALSE
        mock_verify.assert_called_with(self.example_key, EXAMPLE_SECRET)

    def test_verify_keep_trying_until_found_something(self):
        data = {'count': 0}

        def counter(*args, **kwargs):
            output = data['count']
            data['count'] += 1

            return bool(output)

        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            counter,
        ):
            potential_secret = PotentialSecret('test aws', 'test filename', self.example_key)
            assert AWSKeyDetector().verify(
                self.example_key,
                textwrap.dedent("""
                    false_secret = {}
                    real_secret = {}
                """)[1:-1].format(
                    'TEST' * 10,
                    EXAMPLE_SECRET,
                ),
                potential_secret,
            ) == VerifiedResult.VERIFIED_TRUE
        assert potential_secret.other_factors['secret_access_key'] == EXAMPLE_SECRET

    @mock.patch('detect_secrets.plugins.aws.query_aws')
    def test_verify_aws_secret_access_key_valid(self, mock_query_aws):
        mock_query_aws.return_value = mock.MagicMock(status_code=200)
        result = verify_aws_secret_access_key('test-access-key', 'test-secret-access-key')
        mock_query_aws.assert_called_with(
            'test-access-key', 'test-secret-access-key',
            mock.ANY, {
                'Action': 'GetCallerIdentity',
                'Version': '2011-06-15',
            },
        )
        assert result is True

    @mock.patch('detect_secrets.plugins.aws.query_aws')
    def test_verify_aws_secret_access_key_invalid(self, mock_query_aws):
        mock_query_aws.return_value = mock.MagicMock(status_code=403)
        result = verify_aws_secret_access_key('test-access-key', 'test-secret-access-key')
        mock_query_aws.assert_called_with(
            'test-access-key', 'test-secret-access-key',
            mock.ANY, {
                'Action': 'GetCallerIdentity',
                'Version': '2011-06-15',
            },
        )
        assert result is False


@pytest.mark.parametrize(
    'content, expected_output',
    (
        # No quotes
        (
            textwrap.dedent("""
                aws_secret_access_key = {}
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # With quotes
        (
            textwrap.dedent("""
                secret_key = "{}"
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Multiple candidates
        (
            textwrap.dedent("""
                base64_keyA = '{}'
                aws_secret = '{}'
                base64_keyB = '{}'
            """)[1:-1].format(
                'TEST' * 10,

                EXAMPLE_SECRET,

                # This should not be a candidate, because it's not exactly
                # 40 chars long.
                'EXAMPLE' * 7,
            ),
            [
                'TEST' * 10,
                EXAMPLE_SECRET,
            ],
        ),
    ),
)
def test_get_secret_access_key(content, expected_output):
    assert get_secret_access_keys(content) == expected_output
