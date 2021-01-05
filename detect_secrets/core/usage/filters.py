import argparse

from ... import filters
from ...constants import VerifiedResult
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

    verify_group = parser.add_mutually_exclusive_group()
    verify_group.add_argument(
        '-n',
        '--no-verify',
        action='store_true',
        help='Disables additional verification of secrets via network call.',
    )
    verify_group.add_argument(
        '--only-verified',
        action='store_true',
        help='Only flags secrets that can be verified.',
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
    parser.add_argument(
        '--exclude-secrets',
        type=str,
        action='append',
        help='If secrets match this regex, it will be ignored.',
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

    if args.exclude_secrets:
        get_settings().filters['detect_secrets.filters.regex.should_exclude_secret'] = {
            'pattern': args.exclude_secrets,
        }

    if (
        filters.wordlist.is_feature_enabled()
        and args.word_list_file
    ):
        filters.wordlist.initialize(args.word_list_file)

    if not args.no_verify:
        get_settings().filters[
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies'
        ] = {
            'min_level': (
                VerifiedResult.VERIFIED_TRUE
                if args.only_verified
                else VerifiedResult.UNVERIFIED
            ).value,
        }
    else:
        get_settings().disable_filters(
            'detect_secrets.filters.common.is_ignored_due_to_verification_policies',
        )
