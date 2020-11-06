import argparse
import json

from .. import baseline
from .common import initialize_plugin_settings
from .common import valid_path


def add_baseline_option(parser: argparse.ArgumentParser, help: str) -> None:
    parser.add_argument(
        '--baseline',
        nargs=1,
        metavar='FILENAME',
        type=valid_path,
        help=help,
    )


def parse_args(args: argparse.Namespace) -> None:
    if not hasattr(args, 'baseline') or not args.baseline:
        return initialize_plugin_settings(args)

    try:
        with open(args.baseline[0]) as f:
            loaded_baseline = json.loads(f.read())
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        raise argparse.ArgumentTypeError('Unable to read baseline.')

    try:
        args.baseline = baseline.load(loaded_baseline)
    except KeyError:
        raise argparse.ArgumentTypeError('Invalid baseline.')
