from __future__ import absolute_import

import json
import os
import re
import subprocess

from detect_secrets.core.secrets_collection import SecretsCollection


def initialize(
    plugins,
    exclude_files_regex=None,
    exclude_lines_regex=None,
    path='.',
    scan_all_files=False,
):
    """Scans the entire codebase for secrets, and returns a
    SecretsCollection object.

    :type plugins: tuple of detect_secrets.plugins.base.BasePlugin
    :param plugins: rules to initialize the SecretsCollection with.

    :type exclude_files_regex: str|None
    :type exclude_lines_regex: str|None
    :type path: str
    :type scan_all_files: bool

    :rtype: SecretsCollection
    """
    output = SecretsCollection(
        plugins,
        exclude_files=exclude_files_regex,
        exclude_lines=exclude_lines_regex,
    )

    if os.path.isfile(path):
        # This option allows for much easier adhoc usage.
        files_to_scan = [path]
    elif scan_all_files:
        files_to_scan = _get_files_recursively(path)
    else:
        files_to_scan = _get_git_tracked_files(path)

    if not files_to_scan:
        return output

    if exclude_files_regex:
        exclude_files_regex = re.compile(exclude_files_regex, re.IGNORECASE)
        files_to_scan = filter(
            lambda file: (
                not exclude_files_regex.search(file)
            ),
            files_to_scan,
        )

    for file in files_to_scan:
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
    exclude_files_regex = None
    if baseline.exclude_files:
        exclude_files_regex = re.compile(baseline.exclude_files, re.IGNORECASE)

    new_secrets = SecretsCollection()
    for filename in results.data:
        if exclude_files_regex and exclude_files_regex.search(filename):
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


def trim_baseline_of_removed_secrets(results, baseline, filelist):
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

    Note: that the exclude regex is handled separately.

    :type old_baseline: dict
    :param old_baseline: baseline dict, loaded from previous baseline

    :type new_baseline: dict
    :param new_baseline: most recent scan

    :rtype: dict
    """
    new_baseline['results'] = merge_results(
        old_baseline['results'],
        new_baseline['results'],
    )

    return new_baseline


def merge_results(old_results, new_results):
    """Update results in baseline with latest information.

    :type old_results: dict
    :param old_results: results of status quo

    :type new_results: dict
    :param new_results: results to replace status quo

    :rtype: dict
    """
    for filename, old_secrets in old_results.items():
        if filename not in new_results:
            continue

        old_secrets_mapping = dict()
        for old_secret in old_secrets:
            old_secrets_mapping[old_secret['hashed_secret']] = old_secret

        for new_secret in new_results[filename]:
            if new_secret['hashed_secret'] not in old_secrets_mapping:
                # We don't join the two secret sets, because if the newer
                # result set did not discover an old secret, it probably
                # moved.
                continue

            old_secret = old_secrets_mapping[new_secret['hashed_secret']]
            # Only propagate 'is_secret' if it's not already there
            if 'is_secret' in old_secret and 'is_secret' not in new_secret:
                new_secret['is_secret'] = old_secret['is_secret']

    return new_results


def format_baseline_for_output(baseline):
    """
    :type baseline: dict
    :rtype: str
    """
    for filename, secret_list in baseline['results'].items():
        baseline['results'][filename] = sorted(
            secret_list,
            key=lambda x: (x['line_number'], x['hashed_secret'],),
        )

    return json.dumps(
        baseline,
        indent=2,
        sort_keys=True,
        separators=(',', ': '),
    )


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
