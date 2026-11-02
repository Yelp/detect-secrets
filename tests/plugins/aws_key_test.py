import textwrap
from unittest import mock

import pytest
import requests

from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.aws import _is_aws_credential_rejection
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import get_secret_access_keys
from detect_secrets.plugins.aws import verify_aws_secret_access_key
from detect_secrets.util.code_snippet import get_code_snippet


EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


class TestAWSKeyDetector:

    def setup(self):
        self.example_key = 'AKIAZZZZZZZZZZZZZZZZ'

    @pytest.mark.parametrize(
        'line,should_flag',
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
            (
                'A3T0ZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ABIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ACCAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'ASIAZZZZZZZZZZZZZZZZ',
                True,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET),
                True,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET + 'a'),
                False,
            ),
            (
                'aws_access_key = "{}"'.format(EXAMPLE_SECRET[0:39]),
                False,
            ),
        ],
    )
    def test_analyze(self, line, should_flag):
        logic = AWSKeyDetector()

        output = logic.analyze_line(filename='mock_filename', line=line)
        assert len(output) == (1 if should_flag else 0)

    def test_verify_no_secret(self):
        logic = AWSKeyDetector()

        assert logic.verify(
            self.example_key,
            get_code_snippet([], 1),
        ) == VerifiedResult.UNVERIFIED

        assert logic.verify(
            EXAMPLE_SECRET,
            get_code_snippet([], 1),
        ) == VerifiedResult.UNVERIFIED

    def test_verify_valid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=VerifiedResult.VERIFIED_TRUE,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.VERIFIED_TRUE

    def test_verify_invalid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=VerifiedResult.VERIFIED_FALSE,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.VERIFIED_FALSE

    def test_verify_inconclusive_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=VerifiedResult.UNVERIFIED,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.UNVERIFIED

    def test_verify_any_inconclusive_candidate_is_unverified(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            side_effect=[
                VerifiedResult.VERIFIED_FALSE,
                VerifiedResult.UNVERIFIED,
            ],
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(
                    [
                        'false_secret = {0}'.format('TEST' * 10),
                        'unverifiable_secret = {0}'.format(EXAMPLE_SECRET),
                    ],
                    1,
                ),
            ) == VerifiedResult.UNVERIFIED

    def test_verify_keep_trying_until_found_something(self):
        data = {'count': 0}

        def counter(*args, **kwargs):
            output = data['count']
            data['count'] += 1

            return (
                VerifiedResult.VERIFIED_TRUE
                if output
                else VerifiedResult.VERIFIED_FALSE
            )

        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            counter,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(
                    [
                        'false_secret = {0}'.format('TEST' * 10),
                        'real_secret = {0}'.format(EXAMPLE_SECRET),
                    ],
                    1,
                ),
            ) == VerifiedResult.VERIFIED_TRUE


class TestVerifyAwsSecretAccessKey:
    @staticmethod
    def _post_response(status_code, text=''):
        response = mock.Mock()
        response.status_code = status_code
        response.text = text
        return response

    def test_valid_credentials(self):
        with mock.patch(
            'detect_secrets.plugins.aws.requests.post',
            return_value=self._post_response(200),
        ):
            assert verify_aws_secret_access_key(
                'AKIAZZZZZZZZZZZZZZZZ',
                EXAMPLE_SECRET,
            ) == VerifiedResult.VERIFIED_TRUE

    def test_rejected_credentials(self):
        response_text = textwrap.dedent("""\
            <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
              <Error>
                <Type>Sender</Type>
                <Code>InvalidClientTokenId</Code>
                <Message>The security token included in the request is invalid.</Message>
              </Error>
              <RequestId>1234</RequestId>
            </ErrorResponse>
        """)

        with mock.patch(
            'detect_secrets.plugins.aws.requests.post',
            return_value=self._post_response(403, response_text),
        ):
            assert verify_aws_secret_access_key(
                'AKIAZZZZZZZZZZZZZZZZ',
                EXAMPLE_SECRET,
            ) == VerifiedResult.VERIFIED_FALSE

    @pytest.mark.parametrize(
        'status_code, response_text',
        (
            # An egress proxy blocking the request with 403.
            (403, 'BLOCKED by egress proxy: egress to sts.amazonaws.com is not in the allowlist.'),

            # A generic XML error that did not come from STS rejecting credentials.
            (
                403,
                '<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>',
            ),

            # An intermediary answering with an unrelated status code.
            (502, 'Bad Gateway'),
            (504, 'Gateway Timeout'),
        ),
    )
    def test_inconclusive_response_is_not_a_false_negative(self, status_code, response_text):
        with mock.patch(
            'detect_secrets.plugins.aws.requests.post',
            return_value=self._post_response(status_code, response_text),
        ):
            assert verify_aws_secret_access_key(
                'AKIAZZZZZZZZZZZZZZZZ',
                EXAMPLE_SECRET,
            ) == VerifiedResult.UNVERIFIED

    def test_request_exception_is_unverified(self):
        with mock.patch(
            'detect_secrets.plugins.aws.requests.post',
            side_effect=requests.exceptions.ConnectionError,
        ):
            assert verify_aws_secret_access_key(
                'AKIAZZZZZZZZZZZZZZZZ',
                EXAMPLE_SECRET,
            ) == VerifiedResult.UNVERIFIED


@pytest.mark.parametrize(
    'response_text, expected_output',
    (
        ('', False),
        ('BLOCKED by egress proxy', False),
        ('<html><body>Forbidden</body></html>', False),
        ('<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>', True),
        ('<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>', False),
        ('<ErrorResponse><Error><Code></Code></Error></ErrorResponse>', False),
    ),
)
def test_is_aws_credential_rejection(response_text, expected_output):
    assert _is_aws_credential_rejection(response_text) == expected_output


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
    assert get_secret_access_keys(
        get_code_snippet(content.splitlines(), 1),
    ) == expected_output
