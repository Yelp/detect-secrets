from __future__ import absolute_import

import os
import re
import subprocess

from detect_secrets.core.secrets_collection import SecretsCollection


def apply_baseline_filter(results, baseline, filelist):
    """
    :param results:  SecretsCollection of current results
    :param baseline: SecretsCollection of baseline results.
                     This will be updated accordingly (by reference)
    :param filelist: list of strings; filenames that are scanned.
    :returns:        SecretsCollection of new results (filtering out baseline)
    """
    output = SecretsCollection()

    if baseline.exclude_regex:
        regex = re.compile(baseline.exclude_regex, re.IGNORECASE)

    # First, we find all the secrets that are not currently in the baseline.
    for filename in results.data:
        # If the file matches the exclude_regex, we skip it
        if baseline.exclude_regex and regex.search(filename):
            continue
        if filename not in baseline.data:
            # We don't have a previous record of this file, so obviously
            # everything is new.
            output.data[filename] = results.data[filename]
            continue

        # The __hash__ method of PotentialSecret makes this work
        tmp = {secret: secret for secret in results.data[filename] if secret not in baseline.data[filename]}

        if tmp:
            output.data[filename] = tmp

    # If there are new secrets, stop the process here. Otherwise,
    # try to update the baseline with recently removed secrets.
    if len(output.data) > 0:
        return output

    # Only attempt baseline modifications if we don't find any new secrets
    for filename in filelist:
        if filename not in baseline.data:
            # Nothing to modify, because not even there in the first place.
            continue

        if filename not in results.data:
            # All secrets relating to that file was removed.
            del baseline.data[filename]
            continue

        baseline_clone = baseline.data[filename].copy()
        for obj in baseline_clone:
            results_obj = results.get_secret(
                filename,
                obj.secret_hash,
                obj.type
            )
            if results_obj is None:
                # No longer in results, so can remove from baseline
                obj_to_delete = baseline.get_secret(
                    filename,
                    obj.secret_hash,
                    obj.type
                )
                del baseline.data[filename][obj_to_delete]

            elif results_obj.lineno != obj.lineno:
                # Secret moved around, should update baseline with new location
                baseline_obj = baseline.get_secret(
                    filename,
                    obj.secret_hash,
                    obj.type
                )
                baseline_obj.lineno = results_obj.lineno

    return output


def initialize(plugins, exclude_regex=None, rootdir='.'):
    """Scans the entire codebase for high entropy strings, and returns a
    SecretsCollection object.

    :type plugins: tuple of detect_secrets.plugins.base.BasePlugin
    :param plugins: rules to initialize the SecretsCollection with.

    :type exclude_regex: str|None
    :type rootdir: str

    :rtype: SecretsCollection
    """
    output = SecretsCollection(plugins, exclude_regex)

    git_files = _get_git_tracked_files(rootdir)
    if not git_files:
        return output

    if exclude_regex:
        regex = re.compile(exclude_regex, re.IGNORECASE)
        git_files = filter(
            lambda x: not regex.search(x),
            git_files
        )

    for file in git_files:
        output.scan_file(file)

    return output


def _get_git_tracked_files(rootdir='.'):
    """Parsing .gitignore rules is hard.

    However, a way we can get around this problem by just listing all
    currently tracked git files, and start our search from there.
    After all, if it isn't in the git repo, we're not concerned about
    it, because secrets aren't being entered in a shared place.

    :type rootdir: str
    :param rootdir: root directory of where you want to list files from

    :rtype: set|None
    :returns: filepaths to files which git currently tracks (locally)
    """
    try:
        with open(os.devnull, 'w') as fnull:
            git_files = subprocess.check_output(
                [
                    'git',
                    'ls-files',
                    rootdir,
                ],
                stderr=fnull,
            )

        return set(git_files.decode('utf-8').split())
    except subprocess.CalledProcessError:
        return None
