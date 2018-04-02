from __future__ import absolute_import

import os
import subprocess

from detect_secrets.core.log import CustomLog
from detect_secrets_server.repos.base_tracked_repo import BaseTrackedRepo


CustomLogObj = CustomLog()


class LocalTrackedRepo(BaseTrackedRepo):

    def cron(self):
        return "%s %s" % (super(LocalTrackedRepo, self).cron(), '--local')

    @property
    def repo_location(self):
        # When we're performing git commands on a local repository, we need to reference
        # the `/.git` folder within the cloned git repo.
        return os.path.join(self.repo, '.git')

    def clone_and_pull_repo(self):
        # Assumption: If you are scanning a local git repo, then you are "actively"
        # working on it. Therefore, this module will not bear the responsibility
        # of auto-updating the repo with `git pull`.
        pass

    @classmethod
    def get_tracked_filepath_prefix(cls, base_tmp_dir):
        """Returns the directory where the tracked file lives on disk."""
        return '%s/tracked/local' % base_tmp_dir

    @classmethod
    def _get_repo_name(cls, path):
        """
        :type path: string
        :param path: path to git repo
        :return: string
        """
        # First, get the git URL from local repository
        if not path.endswith('/.git'):
            path = os.path.join(path, '.git')
        repo_url = subprocess.check_output([
            'git',
            '--git-dir', path,
            'remote',
            'get-url',
            'origin'
        ], stderr=subprocess.STDOUT).strip()
        return super(LocalTrackedRepo, cls)._get_repo_name(repo_url.decode('utf-8'))

    @classmethod
    def _initialize_tmp_dir(cls, base_tmp_dir):   # pragma: no cover
        super(LocalTrackedRepo, cls)._initialize_tmp_dir(base_tmp_dir)
        tracked_local_dir = base_tmp_dir + '/tracked/local'
        if not os.path.isdir(tracked_local_dir):
            os.makedirs(tracked_local_dir)
