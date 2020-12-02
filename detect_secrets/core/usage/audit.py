import argparse


def add_audit_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'audit',
        help='Manually assesses a baseline to determine validity of secrets found.',
        description=(
            'Auditing a baseline allows analysts to label results, and optimize plugins for '
            'the highest signal-to-noise ratio for their environment.'
        ),
    )

    parser.add_argument(
        'filename',
        nargs='+',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives.'
        ),
    )

    _add_mode_parser(parser)
    _add_statistics_module(parser)
    return parser


def _add_mode_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--diff',
        action='store_true',
        help=(
            'Allows the comparison of two baseline files, in order to '
            'effectively distinguish the difference between various '
            'plugin configurations.'
        ),
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help=(
            'Displays the results of an interactive auditing session '
            'which have been saved to a baseline file.'
        ),
    )


def _add_statistics_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='analytics',
        description=(
            'Quantify the success of your plugins based on the labelled results '
            'in your baseline. To be used with the statisitcs mode (--stats).'
        ),
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format.',
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'audit':
        return

    if args.diff and len(args.filename) != 2:
        raise argparse.ArgumentTypeError(
            '--diff mode requires two files to compare with each other.',
        )
    elif not args.diff and len(args.filename) != 1:
        raise argparse.ArgumentTypeError(
            'Can only specify one baseline at a time.',
        )
