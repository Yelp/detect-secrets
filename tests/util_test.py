import hashlib
import subprocess

import mock
import pytest

from detect_secrets import util
from detect_secrets.plugins.common import filters
from testing.mocks import mock_open

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


def test_build_automaton():
    word_list = """
        foam\n
    """
    with mock_open(
        data=word_list,
        namespace='detect_secrets.util.open',
    ):
        automaton, word_list_hash = util.build_automaton(word_list='will_be_mocked.txt')
        assert word_list_hash == hashlib.sha1('foam'.encode('utf-8')).hexdigest()
        assert filters.is_found_with_aho_corasick(
            secret='foam_roller',
            automaton=automaton,
        )
        assert not filters.is_found_with_aho_corasick(
            secret='no_words_in_word_list',
            automaton=automaton,
        )


def test_get_git_sha():
    with mock.patch.object(
        subprocess,
        'check_output',
        autospec=True,
        return_value=GIT_REPO_SHA,
    ):
        assert util.get_git_sha('.') == GIT_REPO_SHA.decode('utf-8')


def test_get_relative_path_if_in_cwd():
    with mock.patch(
        'detect_secrets.util.os.path.isfile',
        return_value=False,
    ):
        assert (
            util.get_relative_path_if_in_cwd(
                'test_data',
                'config.env',
            ) is None
        )


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
