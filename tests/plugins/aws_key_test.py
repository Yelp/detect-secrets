import textwrap

import mock
import pytest

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import get_secret_access_keys
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
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                '={}'.format(EXAMPLE_SECRET),
            ) == VerifiedResult.VERIFIED_TRUE

    def test_verify_invalid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=False,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                '={}'.format(EXAMPLE_SECRET),
            ) == VerifiedResult.VERIFIED_FALSE

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
            assert AWSKeyDetector().verify(
                self.example_key,
                textwrap.dedent("""
                    false_secret = {}
                    real_secret = {}
                """)[1:-1].format(
                    'TEST' * 10,
                    EXAMPLE_SECRET,
                ),
            ) == VerifiedResult.VERIFIED_TRUE


@pytest.mark.parametrize(
    'content, expected_output',
    (
        # Assignment with no quotes
        (
            textwrap.dedent("""
                aws_secret_access_key = {}
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with no quotes
        (
            textwrap.dedent("""
                some_function({})
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with comma and no quotes
        (
            textwrap.dedent("""
                some_function(foo, {}, bar)
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

        # Function call arg with quotes
        (
            textwrap.dedent("""
                some_function("{}")
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Function call arg with comma and quotes
        (
            textwrap.dedent("""
                some_function('foo', '{}', 'bar')
            """)[1:-1].format(
                EXAMPLE_SECRET,
            ),
            [EXAMPLE_SECRET],
        ),

        # Multiple assignment with quotes candidates
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
