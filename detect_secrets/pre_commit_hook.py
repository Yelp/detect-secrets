import subprocess
import sys
import textwrap

from detect_secrets import VERSION
from detect_secrets.core.baseline import get_non_audited_secrets_from_baseline
from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.baseline import get_verified_non_audited_secrets_from_baseline
from detect_secrets.core.baseline import trim_baseline_of_removed_secrets
from detect_secrets.core.common import write_baseline_to_file
from detect_secrets.core.log import get_logger
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.common import initialize
from detect_secrets.util import build_automaton
from detect_secrets.util import version_check


log = get_logger(format_string='%(message)s')


def parse_args(argv):
    return ParserBuilder()\
        .add_pre_commit_arguments()\
        .parse_args(argv)


def main(argv=None):
    version_check()
    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        log.set_debug_level(args.verbose)

    try:
        # If baseline is provided, we first want to make sure
        # it's valid, before doing any further computation.
        baseline_collection = get_baseline(
            args.baseline[0],
            plugin_filenames=args.plugin_filenames,
        )
    except (IOError, TypeError, ValueError):
        # Error logs handled within logic.
        return 1

    automaton = None
    word_list_hash = None
    if args.word_list_file:
        automaton, word_list_hash = build_automaton(args.word_list_file)

    plugins = initialize.from_parser_builder(
        args.plugins,
        exclude_lines_regex=args.exclude_lines,
        automaton=automaton,
        should_verify_secrets=not args.no_verify,
        plugin_filenames=args.plugin_filenames,
    )

    # Merge plugins from baseline
    if baseline_collection:
        plugins = initialize.merge_plugins_from_baseline(
            baseline_collection.plugins,
            args,
            automaton,
        )
        baseline_collection.plugins = plugins

    results_collection = find_secrets_in_files(args, plugins)
    if baseline_collection:
        original_results_collection = results_collection
        results_collection = get_secrets_not_in_baseline(
            results_collection,
            baseline_collection,
        )

    if len(results_collection.data) > 0:
        pretty_print_diagnostics_for_new_secrets(results_collection)
        return 1

    # if no baseline been supplied
    if not baseline_collection:
        return 0

    # Only attempt baseline modifications if we don't find any new secrets
    baseline_modified = trim_baseline_of_removed_secrets(
        original_results_collection,
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
        return 3

    # check if there are verified but haven't been audited secrets
    verified_non_audited = get_verified_non_audited_secrets_from_baseline(
        baseline_collection,
    )

    if len(verified_non_audited.data) > 0:
        pretty_print_diagnostics_for_verified_non_audited(verified_non_audited)
        return 2

    # check if there are non-audited secrets
    if args.fail_on_unaudited:
        non_audited = get_non_audited_secrets_from_baseline(
            baseline_collection,
        )

        if len(non_audited.data) > 0:
            pretty_print_diagnostics_for_non_audited(non_audited)
            return 4

    return 0


def get_baseline(baseline_filename, plugin_filenames=None):
    """
    :type baseline_filename: string
    :param baseline_filename: name of the baseline file

    :type plugin_filenames: tuple
    :param plugin_filenames: list of plugins to import

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
        plugin_filenames=plugin_filenames,
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
            '   `detect-secrets scan --update {}`\n'
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
    except subprocess.CalledProcessError:  # pragma: no cover
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


def pretty_print_diagnostics_for_verified_non_audited(secrets):
    """Prints a helpful error message for existed verified and non audited secrets

    :type secrets: SecretsCollection
    """
    message = (
        'You have secrets in baseline which have not been audited but have successfully been '
        'use to authenticate against target service.'
    )

    suggestions = [
        'Audit baseline file to make sure you have reviewed the risk',
        'Mark false positives with an inline `pragma: allowlist secret` comment',
        'Commit with `--no-verify` if this is a one-time false positive',
    ]

    _print_warning_header(message)
    _print_secrets_found(secrets)
    _print_mitigation_suggestions(suggestions)
    _print_warning_footer()


def pretty_print_diagnostics_for_non_audited(secrets):
    """Prints a helpful error message for existed non audited secrets

    :type secrets: SecretsCollection
    """
    message = (
        'You have secrets in baseline file which have not been audited yet.'
    )

    suggestions = [
        'Audit baseline file to make sure you have reviewed the risk',
        'Remove the --fail-on-unaudited option from pre-commit hook',
    ]

    _print_warning_header(message)
    _print_secrets_found(secrets)
    _print_mitigation_suggestions(suggestions)
    _print_warning_footer()


def pretty_print_diagnostics_for_new_secrets(secrets):
    """Prints a helpful error message for newly found secrets

    :type secrets: SecretsCollection
    """
    message = (
        'Potential secrets about to be committed to git repo! Please rectify.'
    )

    suggestions = [
        'Mark false positives with an inline `pragma: allowlist secret` comment',
        'Commit with `--no-verify` if this is a one-time false positive',
    ]

    _print_warning_header(message)
    _print_secrets_found(secrets)
    _print_mitigation_suggestions(suggestions)
    _print_warning_footer()


def _print_warning_header(message):
    log.error(textwrap.fill(message))
    log.error('')


def _print_secrets_found(secrets):
    for filename in secrets.data:
        for secret in secrets.data[filename].values():
            log.error(secret)


def _print_mitigation_suggestions(suggestions):
    """
    :type suggestions list of string
    :param suggestions list of string containing the mitigation suggestions.
    """

    wrapper = textwrap.TextWrapper(
        initial_indent='  - ',
        subsequent_indent='    ',
    )

    log.error('Possible mitigations:\n')

    for suggestion in suggestions:
        log.error(wrapper.fill(suggestion))

    log.error('')


def _print_warning_footer():
    log.error(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
