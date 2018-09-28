from __future__ import absolute_import

import json
import subprocess
import sys
import textwrap

from detect_secrets import VERSION
from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.baseline import update_baseline_with_removed_secrets
from detect_secrets.core.log import get_logger
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.core import initialize


log = get_logger(format_string='%(message)s')


def parse_args(argv):
    return ParserBuilder().add_pre_commit_arguments()\
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
        _write_to_baseline_file(
            args.baseline[0],
            baseline_collection.format_for_baseline_output(),
        )

        # The pre-commit framework should automatically detect a file change
        # and print a relevant error message.
        return 1

    return 0


def _write_to_baseline_file(filename, payload):  # pragma: no cover
    """Breaking this function up for mockability."""
    with open(filename, 'w') as f:
        f.write(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                separators=(',', ': '),
            ),
        )


def get_baseline(baseline_filename):
    """
    :raises: IOError
    :raises: ValueError
    """
    if not baseline_filename:
        return

    raise_exception_if_baseline_file_is_not_up_to_date(baseline_filename)

    baseline_string = _get_baseline_string_from_file(baseline_filename)
    baseline_version = json.loads(baseline_string).get('version')

    try:
        raise_exception_if_baseline_version_is_outdated(
            baseline_version,
        )
    except ValueError:
        log.error(
            'The supplied baseline may be incompatible with the current\n'
            'version of detect-secrets. Please recreate your baseline to\n'
            'avoid potential mis-configurations.\n\n'
            'Current Version: %s\n'
            'Baseline Version: %s',
            VERSION,
            baseline_version if baseline_version else '0.0.0',
        )

        raise

    return SecretsCollection.load_baseline_from_string(baseline_string)


def _get_baseline_string_from_file(filename):   # pragma: no cover
    """Breaking this function up for mockability."""
    try:
        with open(filename) as f:
            return f.read()

    except IOError:
        log.error(
            'Unable to open baseline file: %s.', filename,
        )

        raise


def raise_exception_if_baseline_file_is_not_up_to_date(filename):
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


def raise_exception_if_baseline_version_is_outdated(version):
    """
    Version changes may cause breaking changes with past baselines.
    Due to this, we want to make sure that the version that the
    baseline was created with is compatible with the current version
    of the scanner.

    We use semantic versioning, and check for bumps in the MINOR
    version (a good compromise, so we can release patches for other
    non-baseline-related issues, without having all our users
    recreate their baselines again).

    :type version: str|None
    :param version: version of baseline
    :raises: ValueError
    """
    if not version:
        # Baselines created before this change, so by definition,
        # would be outdated.
        raise ValueError

    baseline_version = version.split('.')
    current_version = VERSION.split('.')

    if int(current_version[0]) > int(baseline_version[0]):
        raise ValueError
    elif current_version[0] == baseline_version[0] and \
            int(current_version[1]) > int(baseline_version[1]):
        raise ValueError


def find_secrets_in_files(args):
    plugins = initialize.from_parser_builder(args.plugins)
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
    _print_warning_header()
    _print_secrets_found(secrets)
    _print_mitigation_suggestions()


def _print_warning_header():
    message = (
        'Potential secrets about to be committed to git repo! Please rectify '
        'or explicitly ignore with `pragma: whitelist secret` comment.'
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
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
