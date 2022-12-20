import hashlib
import subprocess
from io import StringIO

import mock
import pytest
import responses
from packaging.version import parse

from detect_secrets import util
from detect_secrets import VERSION
from detect_secrets.plugins.common import filters
from testing.mocks import mock_open
from testing.util import uncolor

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


@responses.activate
def test_version_check_out_of_date():
    responses.add(
        responses.GET,
        (
            'https://detect-secrets-client-version.s3.us-south.'
            'cloud-object-storage.appdomain.cloud/version'
        ),
        status=200,
        body='1000000.0.0+ibm.0',
    )
    with mock.patch('detect_secrets.util.sys.stderr', new=StringIO()) as fakeErr:
        util.version_check()
        stderr = fakeErr.getvalue().strip()
    expected_error_msg = 'WARNING: You are running an outdated version of detect-secrets.\n' + \
        ' Your version: %s\n' % VERSION + \
        ' Latest version: 1000000.0.0+ibm.0\n' + \
        ' See upgrade guide at ' + \
        'https://ibm.biz/detect-secrets-how-to-upgrade\n'
    assert expected_error_msg == uncolor(stderr)


@responses.activate
def test_version_check_not_out_of_date():
    responses.add(
        responses.GET,
        (
            'https://detect-secrets-client-version.s3.us-south.'
            'cloud-object-storage.appdomain.cloud/version'
        ),
        status=200,
        body=VERSION,
    )
    with mock.patch('detect_secrets.util.sys.stderr', new=StringIO()) as fakeErr:
        util.version_check()
        stderr = fakeErr.getvalue().strip()
    expected_error_msg = ''
    assert expected_error_msg == stderr


@responses.activate
def test_verion_check_latest_version_request_fails():
    responses.add(
        responses.GET,
        (
            'https://detect-secrets-client-version.s3.us-south.'
            'cloud-object-storage.appdomain.cloud/version'
        ),
        status=404,
    )
    with mock.patch('detect_secrets.util.sys.stderr', new=StringIO()) as fakeErr:
        util.version_check()
        stderr = fakeErr.getvalue().strip()
    expected_error_msg = 'Failed to check for newer version of detect-secrets.\n'
    assert expected_error_msg == uncolor(stderr)


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


@pytest.mark.parametrize(
    'smaller_version_txt, larger_version_txt',
    [
        ('1', '2'),
        ('1.0.0', '1.0.1'),
        ('1.0.0', '1.0.0+ibm'),
        ('1.0.0+ibm', '1.0.0+ibm.5'),
        ('1.0.0+ibm', '1.0.0+ibm-dss'),
        ('1.0.0+ibm', '1.0.0+ibm.dss'),
        ('1.0.0+ibm.5', '1.0.0+ibm.6'),
        ('1.0.0+ibm.5', '1.0.0+ibm.5.dss'),
        ('1.0.0+ibm.5.dss', '1.0.0+ibm.6.dss'),
        ('1.0.0+ibm.5.dss', '1.0.0+ibm.6.dss.1'),
        ('0.13.0+ibm.6.dss', '0.13.0+ibm.7.dss'),
    ],
)
def test_version_compare(smaller_version_txt, larger_version_txt):
    smaller_version = parse(smaller_version_txt)
    larger_version = parse(larger_version_txt)
    assert smaller_version < larger_version


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
