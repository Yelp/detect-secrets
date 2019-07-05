import subprocess

import mock
import pytest

from detect_secrets import util

GIT_REPO_SHA = b'cbb33d8c545ccf5c55fdcc7d5b0218078598e677'
GIT_REMOTES_VERBOSE_ONE_URL = (
    b'origin\tgit://a.com/a/a.git\t(fetch)\n'
    b'origin\tgit://a.com/a/a.git\t(push)\n'
)
GIT_REMOTES_VERBOSE_TWO_URLS = (
    b'origin\tgit://a.com/a/a.git\t(fetch)\n'
    b'origin\tgit://a.com/a/a.git\t(push)\n'
    b'origin\tgit://b.com/b/b.git\t(fetch)\n'
    b'origin\tgit://b.com/b/b.git\t(push)\n'
)


def test_get_git_sha():
    with mock.patch.object(
        subprocess,
        'check_output',
        autospec=True,
        return_value=GIT_REPO_SHA,
    ):
        assert util.get_git_sha('.') == GIT_REPO_SHA.decode('utf-8')


@pytest.mark.parametrize(
    'git_remotes_result, expected_urls',
    [
        (
            GIT_REMOTES_VERBOSE_ONE_URL,
            {'git://a.com/a/a.git'},
        ),
        (
            GIT_REMOTES_VERBOSE_TWO_URLS,
            {'git://a.com/a/a.git', 'git://b.com/b/b.git'},
        ),
    ],
)
def test_get_git_remotes(
    git_remotes_result,
    expected_urls,
):
    with mock.patch.object(
        subprocess,
        'check_output',
        autospec=True,
        return_value=git_remotes_result,
    ):
        assert expected_urls == set(util.get_git_remotes('.'))
