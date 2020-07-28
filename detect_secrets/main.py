import json
import sys

from detect_secrets.core import audit
from detect_secrets.core import baseline
from detect_secrets.core.common import write_baseline_to_file
from detect_secrets.core.log import log
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.common import initialize
from detect_secrets.util import build_automaton


def parse_args(argv):
    return ParserBuilder()\
        .add_console_use_arguments()\
        .parse_args(argv)


def main(argv=sys.argv[1:]):
    if len(sys.argv) == 1:  # pragma: no cover
        sys.argv.append('--help')

    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        log.set_debug_level(args.verbose)

    if args.action == 'scan':
        automaton = None
        word_list_hash = None
        if args.word_list_file:
            automaton, word_list_hash = build_automaton(args.word_list_file)

        # Plugins are *always* rescanned with fresh settings, because
        # we want to get the latest updates.
        plugins = initialize.from_parser_builder(
            plugins_dict=args.plugins,
            custom_plugin_paths=args.custom_plugin_paths,
            exclude_lines_regex=args.exclude_lines,
            automaton=automaton,
            should_verify_secrets=not args.no_verify,
        )
        if args.string:
            line = args.string

            if isinstance(args.string, bool):
                line = sys.stdin.read().splitlines()[0]

            _scan_string(line, plugins)

        else:
            baseline_dict = _perform_scan(
                args,
                plugins,
                automaton,
                word_list_hash,
            )

            if args.import_filename:
                write_baseline_to_file(
                    filename=args.import_filename[0],
                    data=baseline_dict,
                )
            else:
                print(
                    baseline.format_baseline_for_output(
                        baseline_dict,
                    ),
                )

    elif args.action == 'audit':
        if not args.diff and not args.display_results:
            audit.audit_baseline(args.filename[0])
            return 0

        if args.display_results:
            audit.print_audit_results(args.filename[0])
            return 0

        if len(args.filename) != 2:
            print(
                'Must specify two files to compare!',
                file=sys.stderr,
            )
            return 1

        try:
            audit.compare_baselines(args.filename[0], args.filename[1])
        except audit.RedundantComparisonError:
            print(
                'No difference, because it\'s the same file!',
                file=sys.stderr,
            )

    return 0


def _get_plugins_from_baseline(old_baseline):
    plugins = []
    if old_baseline and 'plugins_used' in old_baseline:
        secrets_collection = SecretsCollection.load_baseline_from_dict(old_baseline)
        plugins = secrets_collection.plugins
    return plugins


def _scan_string(line, plugins):
    longest_plugin_name_length = max(
        map(
            lambda x: len(x.__class__.__name__),
            plugins,
        ),
    )

    output = [
        ('{:%d}: {}' % longest_plugin_name_length).format(
            plugin.__class__.__name__,
            plugin.adhoc_scan(line),
        )
        for plugin in plugins
    ]

    print('\n'.join(sorted(output)))


def _perform_scan(args, plugins, automaton, word_list_hash):
    """
    :param args: output of `argparse.ArgumentParser.parse_args`
    :param plugins: tuple of initialized plugins

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :type word_list_hash: str|None
    :param word_list_hash: optional iterated sha1 hash of the words in the word list.

    :rtype: dict
    """
    old_baseline = _get_existing_baseline(args.import_filename)
    if old_baseline:
        plugins = initialize.merge_plugins_from_baseline(
            _get_plugins_from_baseline(old_baseline),
            args,
            automaton=automaton,
        )

    # Favors CLI arguments over existing baseline configuration
    if old_baseline:
        if not args.exclude_files:
            args.exclude_files = _get_exclude_files(old_baseline)

        if (
            not args.exclude_lines
            and old_baseline.get('exclude')
        ):
            args.exclude_lines = old_baseline['exclude']['lines']

        if (
            not args.word_list_file
            and old_baseline.get('word_list')
        ):
            args.word_list_file = old_baseline['word_list']['file']

        if (
            not args.custom_plugin_paths
            and old_baseline.get('custom_plugin_paths')
        ):
            args.custom_plugin_paths = old_baseline['custom_plugin_paths']

    # If we have knowledge of an existing baseline file, we should use
    # that knowledge and add it to our exclude_files regex.
    if args.import_filename:
        _add_baseline_to_exclude_files(args)

    new_baseline = baseline.initialize(
        path=args.path,
        plugins=plugins,
        custom_plugin_paths=args.custom_plugin_paths,
        exclude_files_regex=args.exclude_files,
        exclude_lines_regex=args.exclude_lines,
        word_list_file=args.word_list_file,
        word_list_hash=word_list_hash,
        should_scan_all_files=args.all_files,
    ).format_for_baseline_output()

    if old_baseline:
        new_baseline = baseline.merge_baseline(
            old_baseline,
            new_baseline,
        )

    return new_baseline


def _get_existing_baseline(import_filename):
    # Favors --update argument over stdin.
    if import_filename:
        return _read_from_file(import_filename[0])
    if not sys.stdin.isatty():
        stdin = sys.stdin.read().strip()
        if stdin:
            return json.loads(stdin)


def _read_from_file(filename):  # pragma: no cover
    """Used for mocking."""
    with open(filename) as f:
        return json.loads(f.read())


def _get_exclude_files(old_baseline):
    """
    Older versions of detect-secrets always had an `exclude_regex` key,
    this was replaced by the `files` key under an `exclude` key in v0.12.0

    :rtype: str|None
    """
    if old_baseline.get('exclude'):
        return old_baseline['exclude']['files']
    if old_baseline.get('exclude_regex'):
        return old_baseline['exclude_regex']


def _add_baseline_to_exclude_files(args):
    """
    Modifies args.exclude_files in-place.
    """
    baseline_name_regex = r'^{}$'.format(args.import_filename[0])

    if not args.exclude_files:
        args.exclude_files = baseline_name_regex
    elif baseline_name_regex not in args.exclude_files:
        args.exclude_files += r'|{}'.format(baseline_name_regex)


if __name__ == '__main__':
    sys.exit(main())
