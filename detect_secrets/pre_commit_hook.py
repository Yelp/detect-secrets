from __future__ import absolute_import

import sys
import textwrap

from detect_secrets.core.baseline import apply_baseline_filter
from detect_secrets.core.log import CustomLog
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins import initialize_plugins


def parse_args(argv):
    return ParserBuilder().add_filenames_argument() \
        .add_set_baseline_argument() \
        .parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        CustomLog.enableDebug(args.verbose)

    try:
        # If baseline is provided, we first want to make sure
        # it's valid, before doing any further computation.
        baseline_collection = get_baseline(args.baseline[0])
    except IOError:
        # Error logs handled in load_baseline_from_file logic.
        return 1

    results = find_secrets_in_files(args)
    if baseline_collection:
        results = apply_baseline_filter(
            results,
            baseline_collection,
            args.filenames
        )

    if len(results.data) > 0:
        pretty_print_diagnostics(results)
        return 1

    return 0


def get_baseline(baseline_filename):
    if not baseline_filename:
        return

    return SecretsCollection.load_baseline_from_file(baseline_filename)


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
    log.error('\n\n')


def _print_secrets_found(log, secrets):
    for filename in secrets.data:
        for secret in secrets.data[filename].values():
            log.error(secret)
    log.error('\n')


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
        log.error('\n')
    log.error('\n')

    log.error(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository'
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
