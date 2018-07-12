from __future__ import absolute_import

import os
import re
import subprocess

from detect_secrets.core.secrets_collection import SecretsCollection


def initialize(plugins, exclude_regex=None, rootdir='.', scan_all_files=False):
    """Scans the entire codebase for high entropy strings, and returns a
    SecretsCollection object.

    :type plugins: tuple of detect_secrets.plugins.base.BasePlugin
    :param plugins: rules to initialize the SecretsCollection with.

    :type exclude_regex: str|None
    :type rootdir: str

    :rtype: SecretsCollection
    """
    output = SecretsCollection(plugins, exclude_regex)

    if os.path.isfile(rootdir):
        # This option allows for much easier adhoc usage.
        git_files = [rootdir]
    elif scan_all_files:
        git_files = _get_files_recursively(rootdir)
    else:
        git_files = _get_git_tracked_files(rootdir)

    if not git_files:
        return output

    if exclude_regex:
        regex = re.compile(exclude_regex, re.IGNORECASE)
        git_files = filter(
            lambda x: not regex.search(x),
            git_files,
        )

    for file in git_files:
        output.scan_file(file)

    return output


def get_secrets_not_in_baseline(results, baseline):
    """
    :type results: SecretsCollection
    :param results: SecretsCollection of current results

    :type baseline: SecretsCollection
    :param baseline: SecretsCollection of baseline results.
                     This will be updated accordingly (by reference)

    :rtype: SecretsCollection
    :returns: SecretsCollection of new results (filtering out baseline)
    """
    regex = None
    if baseline.exclude_regex:
        regex = re.compile(baseline.exclude_regex, re.IGNORECASE)

    new_secrets = SecretsCollection()
    for filename in results.data:
        if regex and regex.search(filename):
            continue

        if filename not in baseline.data:
            # We don't have a previous record of this file, so obviously
            # everything is new.
            new_secrets.data[filename] = results.data[filename]
            continue

        # The __hash__ method of PotentialSecret makes this work
        filtered_results = {
            secret: secret
            for secret in results.data[filename]
            if secret not in baseline.data[filename]
        }

        if filtered_results:
            new_secrets.data[filename] = filtered_results

    return new_secrets


def update_baseline_with_removed_secrets(results, baseline, filelist):
    """
    NOTE: filelist is not a comprehensive list of all files in the repo
    (because we can't be sure whether --all-files is passed in as a
    parameter to pre-commit).

    :type results: SecretsCollection
    :type baseline: SecretsCollection

    :type filelist: list(str)
    :param filelist: filenames that are scanned.

    :rtype: bool
    :returns: True if baseline was updated
    """
    updated = False
    for filename in filelist:
        if filename not in baseline.data:
            # Nothing to modify, because not even there in the first place.
            continue

        if filename not in results.data:
            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It was in the baseline
            #   3. It has no results now.
            del baseline.data[filename]
            updated = True
            continue

        # We clone the baseline, so that we can modify the baseline,
        # without messing up the iteration.
        for baseline_secret in baseline.data[filename].copy():
            new_secret_found = results.get_secret(
                filename,
                baseline_secret.secret_hash,
                baseline_secret.type,
            )

            if not new_secret_found:
                # No longer in results, so can remove from baseline
                old_secret_to_delete = baseline.get_secret(
                    filename,
                    baseline_secret.secret_hash,
                    baseline_secret.type,
                )
                del baseline.data[filename][old_secret_to_delete]
                updated = True

            elif new_secret_found.lineno != baseline_secret.lineno:
                # Secret moved around, should update baseline with new location
                old_secret_to_update = baseline.get_secret(
                    filename,
                    baseline_secret.secret_hash,
                    baseline_secret.type,
                )
                old_secret_to_update.lineno = new_secret_found.lineno
                updated = True

    return updated


def merge_baseline(old_baseline, new_baseline):
    """Updates baseline to be compatible with the latest version of
    detect-secrets.

    Currently, this only exists to transfer whitelisted secrets across
    to the new baseline, and will only work with baselines created
    after v0.9.

    :type old_baseline: dict
    :param old_baseline: baseline dict, loaded from previous baseline

    :type new_baseline: dict
    :param new_baseline: most recent scan
    """
    new_baseline['results'] = merge_results(
        old_baseline['results'],
        new_baseline['results'],
    )

    return new_baseline


def merge_results(old_results, new_results):
    """Update results in baseline with latest information.

    As a rule of thumb, we want to favor the new results, yet at the same
    time, transfer non-modified data from the old results set.

    Assumptions:
        * The list of results in each secret set is in the same order.
          This means that new_results cannot have *more* results than
          old_results.

    :type old_results: dict
    :param old_results: results of status quo

    :type new_results: dict
    :param new_results: results to replace status quo

    :rtype: dict
    """
    for filename, secrets in old_results.items():
        if filename not in new_results:
            new_results[filename] = secrets
            continue

        if len(secrets) == len(new_results[filename]):
            # Assuming that secrets remain in order.
            for index, secrets_tuple in enumerate(zip(secrets, new_results[filename])):
                old_secret, new_secret = secrets_tuple
                if old_secret['hashed_secret'] != new_secret['hashed_secret']:
                    # We don't join the two secret sets, because if the later
                    # result set did not discover an old secret, it's probably
                    # moved.
                    # If it did discover it, then lengths would be different.
                    continue

                if 'is_secret' in old_secret and 'is_secret' not in new_secret:
                    # If the new_secret has a label, then go with the later
                    # version.
                    new_results[filename][index] = old_secret

            continue

        # Need to figure out starting point. That is, while
        # len(new_results) < len(old_results), they may not start at the same
        # place.
        #
        # e.g. old_results = A,B,C,D
        #      new_results = B,C
        first_secret_hash = new_results[filename][0]['hashed_secret']
        for index, secret in enumerate(secrets):
            if secret['hashed_secret'] == first_secret_hash:
                new_results[filename] = secrets[:index] + \
                    new_results[filename] + \
                    secrets[index + len(new_results[filename]):]
                break

    return new_results


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


def _get_files_recursively(rootdir):
    """Sometimes, we want to use this tool with non-git repositories.
    This function allows us to do so.
    """
    output = []
    for root, dirs, files in os.walk(rootdir):
        for filename in files:
            output.append(os.path.join(root, filename))

    return output
