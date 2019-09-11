from __future__ import absolute_import

import textwrap

import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.cloudant import CloudantDetector
from detect_secrets.plugins.cloudant import get_host

CL_HOST = 'testy_test'  # also called user
# only detecting 64 hex
CL_TOKEN = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'


class TestCloudantDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'https://{cl_host}:{cl_token}@{cl_host}.cloudant.com"'.format(
                    cl_host=CL_HOST, cl_token=CL_TOKEN,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_token}@{cl_host}.cloudant.com/_api/v2/'.format(
                    cl_host=CL_HOST, cl_token=CL_TOKEN,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_token}.cloudant.com'.format(
                    cl_host=CL_HOST, cl_token=CL_TOKEN,
                ), False,
            ),
            ('cloudant_password=\'{cl_token}\''.format(cl_token=CL_TOKEN), True),
            ('cloudant_pw=\'{cl_token}\''.format(cl_token=CL_TOKEN), True),
            ('cloudant_pw="{cl_token}"'.format(cl_token=CL_TOKEN), True),
            ('clou_pw = "{cl_token}"'.format(cl_token=CL_TOKEN), True),
            ('cloudant_password = "a-fake-tooshort-key"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = CloudantDetector()
        output = logic.analyze_string(payload, 1, 'mock_filename')

        assert len(output) == (1 if should_flag else 0)

    @responses.activate
    def test_verify_invalid_secret(self):
        cl_api_url = 'https://{cl_host}:{cl_token}@{cl_host}.cloudant.com/_api/v2'.format(
            cl_host=CL_HOST, cl_token=CL_TOKEN,
        )
        responses.add(
            responses.GET, cl_api_url,
            json={'error': 'Access denied. '}, status=401,
        )

        assert CloudantDetector().verify(
            CL_TOKEN,
            'cloudant_host={}'.format(CL_HOST),
        ) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        cl_api_url = 'https://{cl_host}:{cl_token}@{cl_host}.cloudant.com/_api/v2'.format(
            cl_host=CL_HOST, cl_token=CL_TOKEN,
        )
        responses.add(
            responses.GET, cl_api_url,
            json={'id': 1}, status=200,
        )
        potential_secret = PotentialSecret('test cloudant', 'test filename', CL_TOKEN)
        assert CloudantDetector().verify(
            CL_TOKEN,
            'cloudant_host={}'.format(CL_HOST),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE
        assert potential_secret.other_factors['hostname'] == CL_HOST

    @responses.activate
    def test_verify_unverified_secret(self):
        assert CloudantDetector().verify(
            CL_TOKEN,
            'cloudant_host={}'.format(CL_HOST),
        ) == VerifiedResult.UNVERIFIED

    def test_verify_no_secret(self):
        assert CloudantDetector().verify(
            CL_TOKEN,
            'no_un={}'.format(CL_HOST),
        ) == VerifiedResult.UNVERIFIED


@pytest.mark.parametrize(
    'content, expected_output',
    (
        (
            textwrap.dedent("""
                --cloudant-hostname = {}
            """)[1:-1].format(
                CL_HOST,
            ),
            [CL_HOST],
        ),

        # With quotes
        (
            textwrap.dedent("""
                cl_host = "{}"
            """)[1:-1].format(
                CL_HOST,
            ),
            [CL_HOST],
        ),

        # multiple candidates
        (
            textwrap.dedent("""
                cloudant_id = '{}'
                cl-user = '{}'
                CLOUDANT_USERID = '{}'
                cloudant-uname: {}
            """)[1:-1].format(
                CL_HOST,
                'test2_testy_test',
                'test3-testy-testy',
                'notanemail',
            ),
            [
                CL_HOST,
                'test2_testy_test',
                'test3-testy-testy',
                'notanemail',
            ],
        ),
    ),
)
def test_get_host(content, expected_output):
    assert get_host(content) == expected_output
