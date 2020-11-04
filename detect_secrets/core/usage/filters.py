import argparse


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

    parser.add_argument(
        '--word-list',
        type=str,
        help=(
            'Text file with a list of words, '
            'if a secret contains a word in the list we ignore it.'
        ),
        dest='word_list_file',
    )


def parse_args(args: argparse.Namespace) -> None:
    # TODO: do something with settings
    pass
