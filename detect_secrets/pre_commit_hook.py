from __future__ import absolute_import

import subprocess
import sys
import textwrap

from detect_secrets import VERSION
from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.baseline import trim_baseline_of_removed_secrets
from detect_secrets.core.common import write_baseline_to_file
from detect_secrets.core.log import get_logger
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.common import initialize


log = get_logger(format_string='%(message)s')


def parse_args(argv):
    return ParserBuilder()\
        .add_pre_commit_arguments()\
        .parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        log.set_debug_level(args.verbose)

    try:
        # If baseline is provided, we first want to make sure
        # it's valid, before doing any further computation.
        baseline_collection = get_baseline(args.baseline[0])
    except (IOError, ValueError):
        # Error logs handled within logic.
        return 1

    plugins = initialize.from_parser_builder(
        args.plugins,
        exclude_lines_regex=args.exclude_lines,
    )

    # Merge plugin from baseline
    if baseline_collection:
        plugins = initialize.merge_plugin_from_baseline(
            baseline_collection.plugins,
            args,
        )
        baseline_collection.plugins = plugins

    results = find_secrets_in_files(args, plugins)
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
    baseline_modified = trim_baseline_of_removed_secrets(
        original_results,
        baseline_collection,
        args.filenames,
    )

    if VERSION != baseline_collection.version:
        baseline_collection.version = VERSION
        baseline_modified = True

    if baseline_modified:
        write_baseline_to_file(
            filename=args.baseline[0],
            data=baseline_collection.format_for_baseline_output(),
        )

        log.error(
            'The baseline file was updated.\n'
            'Probably to keep line numbers of secrets up-to-date.\n'
            'Please `git add {}`, thank you.\n\n'.format(args.baseline[0]),
        )
        return 1

    return 0


def get_baseline(baseline_filename):
    """
    :raises: IOError
    :raises: ValueError
    """
    if not baseline_filename:
        return

    raise_exception_if_baseline_file_is_unstaged(baseline_filename)

    return SecretsCollection.load_baseline_from_string(
        _get_baseline_string_from_file(
            baseline_filename,
        ),
    )


def _get_baseline_string_from_file(filename):  # pragma: no cover
    """Breaking this function up for mockability."""
    try:
        with open(filename) as f:
            return f.read()

    except IOError:
        log.error(
            'Unable to open baseline file: {}\n'
            'Please create it via\n'
            '   `detect-secrets scan > {}`\n'
            .format(filename, filename),
        )
        raise


def raise_exception_if_baseline_file_is_unstaged(filename):
    """We want to make sure that if there are changes to the baseline
    file, they will be included in the commit. This way, we can keep
    our baselines up-to-date.

    :raises: ValueError
    """
    try:
        files_changed_but_not_staged = subprocess.check_output(
            [
                'git',
                'diff',
                '--name-only',
            ],
        ).split()
    except subprocess.CalledProcessError:
        # Since we don't pipe stderr, we get free logging through git.
        raise ValueError

    if filename.encode() in files_changed_but_not_staged:
        log.error((
            'Your baseline file ({}) is unstaged.\n'
            '`git add {}` to fix this.'
        ).format(
            filename,
            filename,
        ))

        raise ValueError


def find_secrets_in_files(args, plugins):
    collection = SecretsCollection(plugins)

    for filename in args.filenames:
        # Don't scan the baseline file
        if filename == args.baseline[0]:
            continue

        collection.scan_file(filename)

    return collection


def pretty_print_diagnostics(secrets):
    """Prints a helpful error message, for better usability.

    :type secrets: SecretsCollection
    """
    _print_warning_header()
    _print_secrets_found(secrets)
    _print_mitigation_suggestions()


def _print_warning_header():
    message = (
        'Potential secrets about to be committed to git repo! Please rectify '
        'or explicitly ignore with an inline `pragma: whitelist secret` comment.'
    )

    log.error(textwrap.fill(message))
    log.error('')


def _print_secrets_found(secrets):
    for filename in secrets.data:
        for secret in secrets.data[filename].values():
            log.error(secret)


def _print_mitigation_suggestions():
    suggestions = [
        'For information about putting your secrets in a safer place, please ask in #security',
        'Mark false positives with an inline `pragma: whitelist secret` comment',
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
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
