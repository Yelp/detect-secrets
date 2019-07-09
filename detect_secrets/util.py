import os
import subprocess


def get_root_directory():       # pragma: no cover
    return os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '../',
        ),
    )


def get_relative_path(root, path):
    """Returns relative path, after following symlinks."""
    return os.path.realpath(
        os.path.join(root, path),
    )[len(os.getcwd() + '/'):]


def get_git_sha(path):
    """Returns the sha of the git checkout at the input path

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
    at the input path

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
