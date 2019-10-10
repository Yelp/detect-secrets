from __future__ import absolute_import

import textwrap

import pytest
import responses

from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.cloudant import CloudantDetector
from detect_secrets.plugins.cloudant import find_host

CL_HOST = 'testy_test'  # also called user
# only detecting 64 hex CL generated password
CL_PW = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'

# detecting 24 alpha for CL generated API KEYS
CL_API_KEY = 'abcdefghijabcdefghijabcd'


class TestCloudantDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com"'.format(
                    cl_host=CL_HOST, cl_pw=CL_PW,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com/_api/v2/'.format(
                    cl_host=CL_HOST, cl_pw=CL_PW,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com/_api/v2/'.format(
                    cl_host=CL_HOST, cl_pw=CL_PW,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com'.format(
                    cl_host=CL_HOST, cl_pw=CL_PW,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_api_key}@{cl_host}.cloudant.com'.format(
                    cl_host=CL_HOST, cl_api_key=CL_API_KEY,
                ), True,
            ),
            (
                'https://{cl_host}:{cl_pw}.cloudant.com'.format(
                    cl_host=CL_HOST, cl_pw=CL_PW,
                ), False,
            ),
            ('cloudant_password=\'{cl_pw}\''.format(cl_pw=CL_PW), True),
            ('cloudant_pw=\'{cl_pw}\''.format(cl_pw=CL_PW), True),
            ('cloudant_pw="{cl_pw}"'.format(cl_pw=CL_PW), True),
            ('clou_pw = "{cl_pw}"'.format(cl_pw=CL_PW), True),
            ('cloudant_key = "{cl_api_key}"'.format(cl_api_key=CL_API_KEY), True),
            ('cloudant_password = "a-fake-tooshort-key"', False),
            ('cl_api_key = "a-fake-api-key"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = CloudantDetector()
        output = logic.analyze_string(payload, 1, 'mock_filename')

        assert len(output) == (1 if should_flag else 0)

    @responses.activate
    def test_verify_invalid_secret(self):
        cl_api_url = 'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com'.format(
            cl_host=CL_HOST, cl_pw=CL_PW,
        )
        responses.add(
            responses.GET, cl_api_url,
            json={'error': 'unauthorized'}, status=401,
        )

        assert CloudantDetector().verify(
            CL_PW,
            'cloudant_host={}'.format(CL_HOST),
        ) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        cl_api_url = 'https://{cl_host}:{cl_pw}@{cl_host}.cloudant.com'.format(
            cl_host=CL_HOST, cl_pw=CL_PW,
        )
        responses.add(
            responses.GET, cl_api_url,
            json={'id': 1}, status=200,
        )
        potential_secret = PotentialSecret('test cloudant', 'test filename', CL_PW)
        assert CloudantDetector().verify(
            CL_PW,
            'cloudant_host={}'.format(CL_HOST),
            potential_secret,
        ) == VerifiedResult.VERIFIED_TRUE
        assert potential_secret.other_factors['hostname'] == CL_HOST

    @responses.activate
    def test_verify_unverified_secret(self):
        assert CloudantDetector().verify(
            CL_PW,
            'cloudant_host={}'.format(CL_HOST),
        ) == VerifiedResult.UNVERIFIED

    def test_verify_no_secret(self):
        assert CloudantDetector().verify(
            CL_PW,
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
    def test_find_host(self, content, expected_output):
        assert find_host(content) == expected_output
