import hashlib
import os
import subprocess
import sys

import requests
from packaging.version import parse

from detect_secrets import VERSION
from detect_secrets.core.log import get_logger

log = get_logger(format_string='%(message)s')


def version_check():
    # check if running latest version, if not print warning
    # get latest version from GHE
    yellow = '\033[93m'
    end_yellow = '\033[0m'

    current_version = parse(VERSION)
    log.debug(
        'detect-secrets: checking if up-to-date: version=%s',
        current_version,
    )
    try:
        resp = requests.get(
            (
                'https://detect-secrets-client-version.s3.us-south.'
                'cloud-object-storage.appdomain.cloud/version'
            ),
            timeout=5,  # added for COS timeout
        )
        resp.raise_for_status()
        latest_version = parse(resp.text)
        log.debug(
            'detect-secrets: latest_version=%s up-to-date=%r',
            latest_version, current_version >= latest_version,
        )
        if current_version < latest_version:
            print(
                yellow +
                'WARNING: You are running an outdated version of detect-secrets.\n',
                'Your version: %s\n' % current_version,
                'Latest version: %s\n' % latest_version,
                'See upgrade guide at',
                'https://ibm.biz/detect-secrets-how-to-upgrade\n' +
                end_yellow,
                file=sys.stderr,
            )
    except Exception:
        print(
            yellow +
            'Failed to check for newer version of detect-secrets.\n' +
            end_yellow,
            file=sys.stderr,
        )


def build_automaton(word_list):
    """
    :type word_list: str
    :param word_list: optional word list file for ignoring certain words.

    :rtype: (ahocorasick.Automaton, str)
    :returns: an automaton, and an iterated sha1 hash of the words in the word list.
    """
    # Dynamic import due to optional-dependency
    try:
        import ahocorasick
    except ImportError:  # pragma: no cover
        print('Please install the `pyahocorasick` package to use --word-list')
        raise

    # See https://pyahocorasick.readthedocs.io/en/latest/
    # for more information.
    automaton = ahocorasick.Automaton()
    word_list_hash = hashlib.sha1()

    with open(word_list) as f:
        for line in f.readlines():
            # .lower() to make everything case-insensitive
            line = line.lower().strip()
            if len(line) > 3:
                word_list_hash.update(line.encode('utf-8'))
                automaton.add_word(line, line)

    automaton.make_automaton()

    return (
        automaton,
        word_list_hash.hexdigest(),
    )


def get_root_directory():  # pragma: no cover
    return os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '../',
        ),
    )


def get_relative_path_if_in_cwd(root, filepath):
    """Returns relative path, after following symlinks,
    if in current working directory.

    :rtype: str|None
    """
    filepath = os.path.realpath(
        os.path.join(root, filepath),
    )[len(os.getcwd() + '/'):]
    if os.path.isfile(filepath):
        return filepath
    return None


def get_git_sha(path):
    """Returns the sha of the git checkout at the input path.

    :type path: str
    :param path: directory of the git checkout

    :rtype: str|None
    :returns: git sha of the input path
    """
    try:
        with open(os.devnull, 'w') as fnull:
            return subprocess.check_output(
                ['git', 'rev-parse', '--verify', 'HEAD'],
                stderr=fnull,
                cwd=path,
            ).decode('utf-8').split()[0]
    except (subprocess.CalledProcessError, OSError, IndexError):  # pragma: no cover
        return None


def get_git_remotes(path):
    """Returns a list of unique git remotes of the checkout
    at the input path.

    :type path: str
    :param path: directory of the git checkout

    :rtype: List<str>|None
    :returns: A list of unique git urls
    """
    try:
        with open(os.devnull, 'w') as fnull:
            git_remotes = subprocess.check_output(
                ['git', 'remote', '-v'],
                stderr=fnull,
                cwd=path,
            ).decode('utf-8').split('\n')
            return list({
                git_remote.split()[1]
                for git_remote
                in git_remotes
                if len(git_remote) > 2  # split('\n') produces an empty list
            })
    except (subprocess.CalledProcessError, OSError):  # pragma: no cover
        return None
