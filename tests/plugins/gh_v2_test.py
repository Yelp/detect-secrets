from __future__ import absolute_import

import pytest

from detect_secrets.plugins.gh_v2 import GHDetectorV2


class TestGHDetectorV2(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('github-key 2764d47e6bf540911b7da8fe55caa9451e783549', True),
            ('github_pwd :53d49d5081266d939bac57a3d86c517ded974b19', True),
            ('gh-api-key=2764d47e6bf540911b7da8fe55caa9451e783549 ', True),
            ('git-token => "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('"GHE_API_KEY": "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('GITHUB_API_TOKEN := "abcdef0123456789abcdef0123456789abcdef01"', True),
            ('https://username:abcdef0123456789abcdef0123456789abcdef01@github.ibm.com', True,),
            (
                'https://username:abcdef0123456789abcdef0123456789abcdef01@'
                'api.github.ibm.com', True,
            ),
            ('Authorization: token abcdef0123456789abcdef0123456789abcdef01', True),
            (
                'Authorization: Basic '
                'YWJjZWRmYWJlZmQzMzMzMTQ1OTA4YWJjZGRmY2JkZGUxMTQ1Njc4OQo=', True,
            ),
            ('password abcdef0123456789abcdef0123456789abcdef01', True,),
            ('git+https://abcdef0123456789abcdef0123456789abcdef01@github.ibm.com', True,),
            ('sonar.github.oauth=abcdef0123456789abcdef0123456789abcdef01', True,),
            (
                'https://x-oauth-basic:abcdef0123456789abcdef0123456789abcdef01'
                '@github.ibm.com/org/repo.git', True,
            ),
            ('abcdef0123456789abcdef0123456789abcdef01', False),  # no keyword prefix
            ('gh-token=53d49dnotakeyata9bac57a3d86c517ded974b19', False),  # has non-hex
            ('GIT-KEY: a654fd9e3758a65235c765cf51e10df0c80b7a9', False),  # only 39
            ('github_api_key: a654fd9e3758a65235c765cf51e10df0c80b7a923', False),  # 41
            ('gh_key:=2764d47e6bf540911b7da8fe55caa9451e7835492 ', False),
            ('github-api-token: 2764d47e6bf540911b7da8fe55caa9451e783549_ ', False),
            ('git_key=2764d47e6bf540911b7da8fe55caa9451e783549z ', False),
            ('https://<fake-username>:<fake-pass>@github.ibm.com', False),
            (
                'Authorization: llama '
                'YWJjZWRmYWJlZmQzMzMzMTQ1OTA4YWJjZGRmY2JkZGUxMTQ1Njc4OQo=', False,
            ),
            ('Authorization: token %s', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = GHDetectorV2()

        output = logic.analyze_string(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
