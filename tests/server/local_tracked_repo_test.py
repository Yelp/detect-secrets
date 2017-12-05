from __future__ import absolute_import

import subprocess
import unittest

import mock

from detect_secrets.server.local_tracked_repo import LocalTrackedRepo
from tests.server.base_tracked_repo_test import mock_tracked_repo as _mock_tracked_repo
from tests.util.mock_util import mock_subprocess
from tests.util.mock_util import SubprocessMock


def mock_tracked_repo(**kwargs):
    repo_name = kwargs.get('repo_name') or b'git@github.com:pre-commit/pre-commit-hooks'

    # Need to mock out, because __init__ runs `git remote get-url origin`
    with mock.patch(
            'detect_secrets.server.local_tracked_repo.subprocess.check_output',
            autospec=True
    ) as m:
        m.side_effect = mock_subprocess((
            SubprocessMock(
                expected_input='git remote get-url origin',
                mocked_output=repo_name,
            ),
        ))

        output = _mock_tracked_repo(cls=LocalTrackedRepo, **kwargs)

        if 'git_dir' in kwargs:
            m.assert_called_with([
                'git',
                '--git-dir', kwargs.get('git_dir'),
                'remote',
                'get-url',
                'origin'
            ], stderr=subprocess.STDOUT)

        return output


class LocalTrackedRepoTest(unittest.TestCase):

    def test_cron(self):
        repo = mock_tracked_repo()

        assert repo.cron() == \
            '* * 4 * *    detect-secrets-server --scan-repo pre-commit/pre-commit-hooks --local'

    def test_get_repo_name(self):
        assert mock_tracked_repo(
            repo='/Users/morpheus/hooks/pre-commit-hooks',
            git_dir='/Users/morpheus/hooks/pre-commit-hooks/.git',
            repo_name=b'git@github.com:pre-commit/pre-commit-hooks',
        ).name == 'pre-commit/pre-commit-hooks'
