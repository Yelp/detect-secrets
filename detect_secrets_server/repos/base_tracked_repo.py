from __future__ import absolute_import

import codecs
import hashlib
import json
import os
import re
import subprocess
import sys
from enum import Enum

from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.log import CustomLog
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins import initialize
from detect_secrets.plugins import SensitivityValues
from detect_secrets_server.repos.repo_config import RepoConfig


DEFAULT_BASE_TMP_DIR = os.path.expanduser('~/.detect-secrets-server')
IGNORED_FILE_EXTENSIONS = (
    '7z',
    'bmp',
    'bz2',
    'dmg',
    'exe',
    'gif',
    'gz',
    'ico',
    'jar',
    'jpg',
    'jpeg',
    'png',
    'rar',
    'realm',
    's7z',
    'tar',
    'tif',
    'tiff',
    'webp',
    'zip',
)
IGNORED_EXTENSION_REGEX = ''.join('.*\.' + extension + '|' for extension in IGNORED_FILE_EXTENSIONS)[:-1]

CustomLogObj = CustomLog()


class OverrideLevel(Enum):
    NEVER = 0
    ASK_USER = 1
    ALWAYS = 2


def get_filepath_safe(prefix, file):
    """Attempts to prevent file traversal when trying to get `prefix/file`"""
    prefix_realpath = os.path.realpath(prefix)
    filepath = os.path.realpath('%(prefix_realpath)s/%(file)s' % {'prefix_realpath': prefix_realpath, 'file': file})
    if not filepath.startswith(prefix_realpath):
        return None

    return filepath


class BaseTrackedRepo(object):

    def __init__(
            self,
            sha,
            repo,
            plugin_sensitivity,
            repo_config,
            cron='',
            **kwargs
    ):
        """
        :type sha: string
        :param sha: last commit hash scanned

        :type repo: string
        :param repo: git URL or local path of repo

        :type plugin_sensitivity: SensitivityValues
        :param plugin_sensitivity: values to configure various plugins

        :type repo_config: RepoConfig
        :param repo_config: values to configure repos, See `server_main` for more
                      details.

        :type cron: string
        :param cron: crontab syntax
        """
        self.last_commit_hash = sha
        self.repo = repo
        self.crontab = cron
        self.plugin_config = plugin_sensitivity
        self.base_tmp_dir = repo_config.base_tmp_dir
        self.baseline_file = repo_config.baseline
        self.exclude_regex = repo_config.exclude_regex

        self.name = self._get_repo_name(repo)

        self._initialize_tmp_dir(repo_config.base_tmp_dir)

    @classmethod
    def load_from_file(cls, repo_name, repo_config, *args, **kwargs):
        """This will load a TrackedRepo to memory, from a given tracked file.
        For automated management without a database.

        :type repo_name: string
        :param repo_name: git URL or local path of repo

        :type repo_config: RepoConfig
        :param repo_config: values to configure repos, See `server_main` for more
                      details.

        :return: TrackedRepo
        """
        repo_name = cls._get_repo_name(repo_name)

        data = cls._read_tracked_file(repo_name, repo_config.base_tmp_dir)
        if data is None:
            return None

        data = cls._modify_tracked_file_contents(data)

        # Add server-side configuration to repo
        data['repo_config'] = RepoConfig(
            base_tmp_dir=repo_config.base_tmp_dir,
            exclude_regex=repo_config.exclude_regex,
            baseline=data['baseline_file'],
        )

        return cls(**data)

    def cron(self):
        """Returns the cron command to be appended to crontab"""
        return '%(crontab)s    detect-secrets-server --scan-repo %(name)s' % {
            'crontab': self.crontab,
            'name': self.name,
        }

    def scan(self):
        """Clones the repo, and scans the git diff between last_commit_hash and HEAD.

        :raises: subprocess.CalledProcessError
        """
        self.clone_and_pull_repo()
        diff = self._get_latest_changes()
        baseline = self._get_baseline()

        default_plugins = initialize(self.plugin_config)

        secrets = SecretsCollection(default_plugins, self.exclude_regex)

        secrets.scan_diff(
            diff,
            baseline_filename=baseline,
            last_commit_hash=self.last_commit_hash,
            repo_name=self.name
        )

        if baseline:
            baseline_collection = SecretsCollection.load_baseline_from_string(baseline)
            secrets = get_secrets_not_in_baseline(secrets, baseline_collection)

        return secrets

    def update(self):
        """Updates TrackedRepo to latest commit.

        :raises: subprocess.CalledProcessError
        """

        sha = subprocess.check_output([
            'git',
            '--git-dir', self.repo_location,
            'rev-parse',
            'HEAD'
        ], stderr=subprocess.STDOUT)

        self.last_commit_hash = sha.decode('ascii').strip()

    def save(self, override_level=OverrideLevel.ASK_USER):
        """Saves tracked repo config to file. Returns True if successful.

        :type override_level: OverrideLevel
        :param override_level: determines if we overwrite the JSON file, if exists.
        """
        if self.tracked_file_location is None:
            return False

        # If file exists, check OverrideLevel
        if os.path.isfile(self.tracked_file_location):
            if override_level == OverrideLevel.NEVER:
                return False

            elif override_level == OverrideLevel.ASK_USER:
                if not self._prompt_user_override():
                    return False

        with codecs.open(self.tracked_file_location, 'w') as f:
            f.write(json.dumps(self.__dict__, indent=2))

        return True

    @property
    def repo_location(self):
        return get_filepath_safe(
            '%s/repos' % self.base_tmp_dir,
            self.internal_filename
        )

    @property
    def internal_filename(self):
        return hashlib.sha512(self.name.encode('utf-8')).hexdigest()

    @property
    def tracked_file_location(self):
        return self._get_tracked_file_location(
            self.base_tmp_dir,
            self.internal_filename
        )

    @classmethod
    def _initialize_tmp_dir(self, base_tmp_dir):  # pragma: no cover
        """Make base tmp folder, if non-existent."""
        if not os.path.isdir(base_tmp_dir):
            os.makedirs(base_tmp_dir)
            os.makedirs(base_tmp_dir + '/repos')
            os.makedirs(base_tmp_dir + '/tracked')

    @classmethod
    def _get_repo_name(cls, url):
        """Obtains the repo name repo URL.
        This allows for local file saving, as compared to the URL, which indicates WHERE to clone from.

        :type url: string
        """
        # e.g. 'git@github.com:pre-commit/pre-commit-hooks' -> pre-commit/pre-commit-hooks
        name = url.split(':')[-1]

        # The url_or_path will still work without the `.git` suffix.
        if name.endswith('.git'):
            return name[:-4]

        return name

    def clone_and_pull_repo(self):
        """We want to update the repository that we're tracking, to get the latest changes.
        Then, we can subsequently scan these new changes.

        :raises: subprocess.CalledProcessError
        """
        # We clone a bare repo, because we're not interested in the files themselves.
        # This will be more space efficient for local disk storage.
        try:
            subprocess.check_output([
                'git',
                'clone',
                self.repo,
                self.repo_location,
                '--bare'
            ], stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode('ascii')

            # Ignore this message, because it's expected if the repo has already been tracked.
            match = re.match(r"fatal: destination path '[^']+' already exists", error_msg)
            if not match:
                raise

        subprocess.check_output([
            'git',
            '--git-dir', self.repo_location,
            '--work-tree', '.',
            'pull',
        ], stderr=subprocess.STDOUT)

    def get_blame(self, line_number, filename):
        """
        :return: string

        :raises: subprocess.CalledProcessError
        """
        return subprocess.check_output([
            'git',
            '--git-dir', self.repo_location,
            '--work-tree', '.',
            'blame',
            self.get_main_branch(),
            '-L', '{0},{1}'.format(line_number, line_number),
            '--show-email',
            '--line-porcelain',
            '--', filename,
        ], stderr=subprocess.STDOUT).decode('utf-8')

    def get_main_branch(self):
        """
        :return: string
                 e.g. master most of the time
        :raises: subprocess.CalledProcessError
        """
        return subprocess.check_output([
            'git',
            '--git-dir',
            self.repo_location,
            'rev-parse',
            '--abbrev-ref',
            'HEAD'
        ], stderr=subprocess.STDOUT).strip()

    def _get_latest_changes(self):  # pragma: no cover
        """
        :return: string
                 This will be the patch file format of difference between last saved "clean"
                 commit hash, and HEAD.

        :raises: subprocess.CalledProcessError
        """
        try:
            filenames_in_diff = subprocess.check_output([
                'git',
                '--git-dir', self.repo_location,
                'diff', self.last_commit_hash, 'HEAD',
                '--name-only'
            ], stderr=subprocess.STDOUT).decode('utf-8', 'ignore').splitlines()

            trimmed_filesnames = [filename for filename in filenames_in_diff
                                  if not re.match(IGNORED_EXTENSION_REGEX, filename)]

            args = [
                'git',
                '--git-dir', self.repo_location,
                'diff', self.last_commit_hash, 'HEAD',
                '--',
            ]
            args.extend(trimmed_filesnames)
            diff = subprocess.check_output(args, stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError:
            repo_location_exists = os.path.exists(self.repo_location)
            head_exists = os.path.exists(self.repo_location + '/logs/HEAD')
            first_line = ''
            if head_exists:
                with open(self.repo_location + '/logs/HEAD', 'r') as f:
                    first_line = f.readline().strip()
            alert = {
                'alert': 'Hash not found when diffing',
                'hash': self.last_commit_hash,
                'repo_location': self.repo_location,
                'repo_name': self.name,
            }
            if not repo_location_exists:
                alert['info'] = 'self.repo_location does not exist'
            elif not head_exists:
                alert['info'] = 'logs/HEAD does not exist'
            else:
                alert['info'] = 'first_line of logs/HEAD is ' + str(first_line)
            CustomLogObj.getLogger().error(alert)

            # The last_commit_hash may have been removed from the git logs,
            # or detect-secrets is being run on an out-of-date repo, in which case it may re-alert on old secrets now.
            self.update()
            return ''

        return diff.decode('utf-8', 'ignore')

    def _get_baseline(self):
        """Take the most updated baseline, because want to get the most updated
        baseline. Note that this means it's still "user-dependent", but at the
        same time, we want to ignore new explicit whitelists.
        Also, this would mean that we **always** get a whitelist, if exists
        (rather than worrying about fixing on a commit that has a whitelist)

        :return: file contents of baseline_file
        :raises: subprocess.CalledProcessError
        """
        if not self.baseline_file:
            return

        try:
            baseline = subprocess.check_output([
                'git',
                '--git-dir', self.repo_location,
                'show', 'HEAD:%s' % self.baseline_file,
            ], stderr=subprocess.STDOUT)

            return baseline.decode('ascii')

        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode('ascii')

            # Some repositories may not have baselines.
            # This is a non-breaking error, if so.
            match = re.match(r"fatal: Path '[^']+' does not exist", error_msg)
            if not match:
                raise

    @classmethod
    def get_tracked_filepath_prefix(cls, base_tmp_dir):
        """Returns the directory where the tracked file lives on disk."""
        return '%s/tracked' % base_tmp_dir

    @classmethod
    def _get_tracked_file_location(cls, base_tmp_dir, internal_filename):
        """We use the file system (instead of a DB) to track and monitor changes to
        all TrackedRepos. This function returns where this file lives.

        :return: string
        """
        return get_filepath_safe(
            cls.get_tracked_filepath_prefix(base_tmp_dir),
            internal_filename + '.json'
        )

    @classmethod
    def _read_tracked_file(cls, repo_name, base_tmp_dir):
        """
        :type repo_name: string
        :param repo_name: name of repo to scan
        :return: TrackedRepo __dict__ representation
        """
        # We need to manually get the `internal_name` of the repo, to know which file to read from.
        filename = cls._get_tracked_file_location(
            base_tmp_dir,
            hashlib.sha512(repo_name.encode('utf-8')).hexdigest()
        )
        if not filename:
            return None

        try:
            with codecs.open(filename) as f:
                return json.loads(f.read())
        except (IOError, ValueError, TypeError):
            CustomLogObj.getLogger().error(
                'Unable to open repo data file: %s. Aborting.', filename,
            )
            return None

    def _prompt_user_override(self):  # pragma: no cover
        """Prompts for user input to check if should override file.
        :return: bool
        """
        # Make sure to write to stderr, because crontab output is going to be to stdout
        sys.stdout = sys.stderr

        override = None
        while override not in ['y', 'n']:
            override = str(input(
                '"%s" repo already tracked! Do you want to override this (y|n)? ' % self.name
            )).lower()

        sys.stdout = sys.__stdout__

        if override == 'n':
            return False
        return True

    @classmethod
    def _modify_tracked_file_contents(cls, data):
        """For better representation, we use namedtuples. However, these do not directly
        correlate to file dumps (which `save` does, using `__dict__`. Therefore, we may
        need to modify these values, before loading them into the class constructor.

        :type data: dict
        :param data: pretty much the layout of __dict__
        :return: dict
        """
        # Need to change plugins to type SensitivityValues
        data['plugin_sensitivity'] = SensitivityValues(**data['plugins'])

        return data

    @property
    def __dict__(self):
        """This is written to the filesystem, and used in load_from_file.
        Should contain all variables needed to initialize TrackedRepo."""
        output = {
            'sha': self.last_commit_hash,
            'repo': self.repo,
            'plugins': {},
            'cron': self.crontab,
            'baseline_file': self.baseline_file,
        }

        # Add plugin_config
        for plugin_name in self.plugin_config._fields:
            output['plugins'][plugin_name] = getattr(self.plugin_config, plugin_name)

        return output
