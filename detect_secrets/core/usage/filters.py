import argparse

from ... import filters
from ...settings import get_settings
from .common import valid_path


def add_filter_options(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='filter options',
        description=(
            'Configure settings for filtering out secrets after they are flagged '
            'by the engine.'
        ),
    )

    parser.add_argument(
        '-n',
        '--no-verify',
        action='store_true',
        help='Disables additional verification of secrets via network call.',
    )

    parser.add_argument(
        '--exclude-lines',
        type=str,
        help='If lines match this regex, it will be ignored.',
    )
    parser.add_argument(
        '--exclude-files',
        type=str,
        help='If filenames match this regex, it will be ignored.',
    )

    if filters.wordlist.is_feature_enabled():
        parser.add_argument(
            '--word-list',
            type=valid_path,
            help=(
                'Text file with a list of words, '
                'if a secret contains a word in the list we ignore it.'
            ),
            dest='word_list_file',
        )


def parse_args(args: argparse.Namespace) -> None:
    if args.exclude_lines:
        get_settings().filters['detect_secrets.filters.regex.should_exclude_line'] = {
            'pattern': args.exclude_lines,
        }

    if args.exclude_files:
        get_settings().filters['detect_secrets.filters.regex.should_exclude_file'] = {
            'pattern': args.exclude_files,
        }

    if (
        filters.wordlist.is_feature_enabled()
        and args.word_list_file
    ):
        filters.wordlist.initialize(args.word_list_file)
