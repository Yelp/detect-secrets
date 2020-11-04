import argparse


def add_audit_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser('audit')

    parser.add_argument(
        'filename',
        nargs='+',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives.'
        ),
    )

    _add_mode_parser(parser)
    return parser


def _add_mode_parser(parser: argparse.ArgumentParser) -> None:
    mode_parser = parser.add_mutually_exclusive_group()
    mode_parser.add_argument(
        '--diff',
        action='store_true',
        help=(
            'Allows the comparison of two baseline files, in order to '
            'effectively distinguish the difference between various '
            'plugin configurations.'
        ),
    )

    mode_parser.add_argument(
        '--stats',
        action='store_true',
        help=(
            'Displays the results of an interactive auditing session '
            'which have been saved to a baseline file.'
        ),
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
