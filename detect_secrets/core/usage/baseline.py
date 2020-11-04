import argparse
import json

from ...settings import configure_settings_from_baseline
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

    args.baseline = args.baseline[0]

    try:
        configure_settings_from_baseline(args.baseline)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        raise argparse.ArgumentTypeError('Unable to read baseline.')
    except KeyError:
        raise argparse.ArgumentTypeError('Invalid baseline.')
