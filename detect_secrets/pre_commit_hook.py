from __future__ import absolute_import

import json
import subprocess
import sys
import textwrap

from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.baseline import update_baseline_with_removed_secrets
from detect_secrets.core.log import CustomLog
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins import initialize_plugins


def parse_args(argv):
    return ParserBuilder().add_pre_commit_arguments()\
        .parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        CustomLog.enableDebug(args.verbose)

    try:
        # If baseline is provided, we first want to make sure
        # it's valid, before doing any further computation.
        baseline_collection = get_baseline(args.baseline[0])
    except (IOError, ValueError):
        # Error logs handled in load_baseline_from_file logic.
        return 1

    results = find_secrets_in_files(args)
    if baseline_collection:
        original_results = results
        results = get_secrets_not_in_baseline(
            results,
            baseline_collection,
        )

    if len(results.data) > 0:
        pretty_print_diagnostics(results)
        return 1

    if not baseline_collection:
        return 0

    # Only attempt baseline modifications if we don't find any new secrets
    successful_update = update_baseline_with_removed_secrets(
        original_results,
        baseline_collection,
        args.filenames,
    )
    if successful_update:
        with open(args.baseline[0], 'w') as f:
            f.write(
                json.dumps(
                    baseline_collection.format_for_baseline_output(),
                    indent=2,
                    sort_keys=True
                )
            )

        # The pre-commit framework should automatically detect a file change
        # and print a relevant error message.
        return 1

    return 0


def get_baseline(baseline_filename):
    """
    :raises: IOError
    :raises: ValueError
    """
    if not baseline_filename:
        return

    raise_exception_if_baseline_file_is_not_up_to_date(baseline_filename)

    return SecretsCollection.load_baseline_from_file(baseline_filename)


def raise_exception_if_baseline_file_is_not_up_to_date(filename):
    """We want to make sure that if there are changes to the baseline
    file, they will be included in the commit. This way, we can keep
    our baselines up-to-date.

    :raises: ValueError
    """
    try:
        files_changed_but_not_staged = subprocess.check_output(
            'git diff --name-only'.split()
        ).split()
    except subprocess.CalledProcessError:
        # Since we don't pipe stderr, we get free logging through git.
        raise ValueError

    if filename.encode() in files_changed_but_not_staged:
        CustomLog(formatter='%(message)s').getLogger()\
            .error((
                'Your baseline file ({}) is unstaged.\n'
                '`git add {}` to fix this.'
            ).format(
                filename,
                filename,
            ))

        raise ValueError


def find_secrets_in_files(args):
    plugins = initialize_plugins(args.plugins)
    collection = SecretsCollection(plugins)

    for filename in args.filenames:
        if filename == args.baseline[0]:
            # Obviously, don't detect the baseline file
            continue

        collection.scan_file(filename)

    return collection


def pretty_print_diagnostics(secrets):
    """Prints a helpful error message, for better usability.

    :type secrets: SecretsCollection
    """
    log = CustomLog(formatter='%(message)s').getLogger()

    _print_warning_header(log)
    _print_secrets_found(log, secrets)
    _print_mitigation_suggestions(log)


def _print_warning_header(log):
    message = (
        'Potential secrets about to be committed to git repo! Please rectify '
        'or explicitly ignore with `pragma: whitelist secret` comment.'
    )

    log.error(textwrap.fill(message))
    log.error('')


def _print_secrets_found(log, secrets):
    for filename in secrets.data:
        for secret in secrets.data[filename].values():
            log.error(secret)


def _print_mitigation_suggestions(log):
    suggestions = [
        'For information about putting your secrets in a safer place, please ask in #security',
        'Mark false positives with `# pragma: whitelist secret`',
        'Commit with `--no-verify` if this is a one-time false positive',
    ]

    wrapper = textwrap.TextWrapper(
        initial_indent='  - ',
        subsequent_indent='    ',
    )

    log.error('Possible mitigations:\n')

    for suggestion in suggestions:
        log.error(wrapper.fill(suggestion))

    log.error('')

    log.error(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository'
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
