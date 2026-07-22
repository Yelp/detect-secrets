import textwrap
from unittest import mock

import pytest

from detect_secrets.constants import VerifiedResult
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.aws import _interpret_sts_response
from detect_secrets.plugins.aws import get_secret_access_keys
from detect_secrets.util.code_snippet import get_code_snippet


EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


class TestAWSKeyDetector:

    def setup_method(self):
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
            return_value=True,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.VERIFIED_TRUE

    def test_verify_invalid_secret(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=False,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
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
                get_code_snippet(
                    [
                        'false_secret = {0}'.format('TEST' * 10),
                        'real_secret = {0}'.format(EXAMPLE_SECRET),
                    ],
                    1,
                ),
            ) == VerifiedResult.VERIFIED_TRUE

    def test_verify_proxy_403_is_unverified(self):
        with mock.patch(
            'detect_secrets.plugins.aws.verify_aws_secret_access_key',
            return_value=None,
        ):
            assert AWSKeyDetector().verify(
                self.example_key,
                get_code_snippet(['={}'.format(EXAMPLE_SECRET)], 1),
            ) == VerifiedResult.UNVERIFIED


class TestInterpretStsResponse:

    def _response(self, status_code, text):
        response = mock.Mock()
        response.status_code = status_code
        response.text = text
        return response

    def test_proxy_403_without_sts_body_is_incomplete(self):
        assert _interpret_sts_response(
            self._response(403, 'BLOCKED by egress proxy: sts.amazonaws.com'),
        ) is None

    def test_sts_invalid_token_is_false(self):
        body = (
            '<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            '<Error><Code>InvalidClientTokenId</Code>'
            '<Message>The security token included in the request is invalid.'
            '</Message></Error></ErrorResponse>'
        )
        assert _interpret_sts_response(self._response(403, body)) is False

    def test_sts_success_is_true(self):
        body = (
            '<GetCallerIdentityResponse '
            'xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            '<GetCallerIdentityResult><Arn>arn:aws:iam::1:user/x'
            '</Arn></GetCallerIdentityResult>'
            '</GetCallerIdentityResponse>'
        )
        assert _interpret_sts_response(self._response(200, body)) is True

    def test_empty_403_is_incomplete(self):
        assert _interpret_sts_response(self._response(403, '')) is None


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
