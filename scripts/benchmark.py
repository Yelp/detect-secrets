#!/usr/bin/python3
import argparse
import json
import os
import statistics
import subprocess
import sys

from monotonic import monotonic

from detect_secrets.core.color import AnsiColor
from detect_secrets.core.color import colorize
from detect_secrets.core.usage import PluginOptions
from detect_secrets.util import get_root_directory


def main():
    args = get_arguments()

    print(
        'Running performance tests on: {}'.format(
            ', '.join(args.plugin),
        ),
        file=sys.stderr,
    )
    print(
        'for: {}'.format(args.filenames),
        file=sys.stderr,
    )

    # First, convert chosen plugins into their disabled flags
    always_disabled_plugins = []
    flag_list = {}
    for info in PluginOptions.all_plugins:
        if info.classname in args.plugin:
            flag_list[info.disable_flag_text] = info.classname
        else:
            always_disabled_plugins.append(info.disable_flag_text)

    # Then, iterate through each disabled flag, toggling them off
    # individually.
    timings = {}
    if len(args.plugin) == len(PluginOptions.all_plugins):
        # Only run benchmarks for all the cases, if already running all plugins
        timings['all-plugins'] = time_execution(
            filenames=args.filenames,
            timeout=args.harakiri,
            num_iterations=args.num_iterations,
        )

    for flag_number, flag in enumerate(flag_list):
        plugins_to_ignore = list(flag_list.keys())
        plugins_to_ignore.pop(flag_number)

        key = flag_list[flag]
        timings[key] = time_execution(
            filenames=args.filenames,
            timeout=args.harakiri,
            num_iterations=args.num_iterations,
            flags=plugins_to_ignore + always_disabled_plugins,
        )

    print_output(timings, args)


def get_arguments():
    plugins = [
        info.classname
        for info in PluginOptions.all_plugins
    ]

    parser = argparse.ArgumentParser(description='Run some benchmarks.')
    parser.add_argument(
        'filenames',
        nargs=argparse.REMAINDER,
        help='Filenames to check or detect-secrets compatible arguments.',
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Human readable output.',
    )
    parser.add_argument(
        '--plugin',
        default=None,       # needs to be None, otherwise append won't work as expected
        choices=plugins,
        action='append',
        help=(
            'Specifies a plugin to test. May provide multiple values. '
            'Defaults to all.'
        ),
    )
    parser.add_argument(
        '--harakiri',
        default=5,
        type=assert_positive(float),
        help=(
            'Specifies an upper bound for the number of seconds to wait '
            'per execution.'
        ),
    )
    parser.add_argument(
        '-n',
        '--num-iterations',
        default=1,
        type=assert_positive(int),
        help=(
            'Specifies the number of times to run the test. '
            'Results will be averaged over this value.'
        ),
    )
    parser.add_argument(
        '--baseline',
        type=assert_valid_file,
        help=(
            'If provided, will compare performance with provided baseline. '
            'Assumes pretty output (otherwise, you can do the comparison '
            'yourself).'
        ),
    )

    args = parser.parse_args()
    if not args.filenames:
        if args.baseline:
            args.filenames = args.baseline['filenames']
        else:
            args.filenames = [get_root_directory()]

    if not args.plugin:
        args.plugin = plugins

    return args


def assert_positive(type):
    def wrapped(string):
        value = type(string)
        if value <= 0:
            raise argparse.ArgumentTypeError(
                '{} must be a positive {}.'.format(
                    string,
                    type.__name__,
                ),
            )

        return value

    return wrapped


def assert_valid_file(string):
    if not os.path.isfile(string):
        raise argparse.ArgumentTypeError(
            '{} must be a valid file.'.format(string),
        )

    with open(string) as f:
        return json.load(f)


def time_execution(filenames, timeout, num_iterations=1, flags=None):
    """
    :type filenames: list
    :type timeout: float
    :type num_iterations: int

    :type flags: list|None
    :param flags: flags to disable
    """
    if not flags:
        flags = []

    scores = []
    for _ in range(num_iterations):
        start_time = monotonic()
        try:
            subprocess.check_output(
                'detect-secrets scan'.split() + filenames + flags,
                timeout=timeout,
            )
            scores.append(monotonic() - start_time)
        except subprocess.TimeoutExpired:
            scores.append(timeout)

    result = statistics.mean(scores)
    if result == timeout:
        return None

    return round(statistics.mean(scores), 5)


def print_output(timings, args):
    """
    :type timings: dict
    :type args: Namespace
    """
    if not args.pretty and not args.baseline:
        print(
            json.dumps({
                'filenames': args.filenames,
                'timings': timings,
            }),
        )
        return

    # Print header
    baseline = args.baseline['timings'] if args.baseline else {}
    if not baseline:
        print('-' * 45)
        print('{:<25s}{:>15s}'.format('plugin', 'time'))
        print('-' * 45)
    else:
        print('-' * 60)
        print('{:<25s}{:>11s}{:>22s}'.format('plugin', 'time', 'change'))
        print('-' * 60)

    # Print content
    if 'all-plugins' in timings:
        print_line(
            'All Plugins',
            time=timings['all-plugins'],
            baseline=_get_baseline_value(baseline, 'all-plugins'),
            timeout=args.harakiri,
        )
        del timings['all-plugins']

    for key in sorted(timings):
        print_line(
            key,
            time=timings[key],
            baseline=_get_baseline_value(baseline, key),
            timeout=args.harakiri,
        )

    # Print footer line
    if not args.baseline:
        print('-' * 45)
    else:
        print('-' * 60)


def _get_baseline_value(baseline, key):
    """
    We need to distinguish between no baseline mode (which should return
    None as a value), baseline mode with exceeded timeout (which is stored
    as None, but should return 0).
    """
    if key in baseline:
        return 0 if baseline[key] is None else baseline[key]


def print_line(name, time, baseline, timeout):
    """
    :type name: str

    :type time: float
    :param time: seconds it took to execute

    :type baseline: float
    :param baseline: expected seconds to execute

    :type timeout: float
    :param timeout: used to calculate difference when either current
        execution or baseline execution exceeds timeout.
    """
    if not time:
        time_string = 'Timeout exceeded!'
    else:
        time_string = '{}s'.format(str(time))

    if baseline is not None:
        if time and baseline:
            difference = round(baseline - time, 2)
        elif time:
            # This handles the case when the baseline execution exceeds timeout
            difference = round(timeout - time, 2)
        elif baseline:
            # This handles the case when this current execution exceeds timeout
            difference = round(timeout - baseline, 2)
        else:
            # They both failed.
            difference = 0

        if difference > 0:
            difference_string = colorize(
                '▲  {}'.format(difference),
                AnsiColor.LIGHT_GREEN,
            )
            difference_string = '{:>22s}'.format(difference_string)
        elif difference < 0:
            difference_string = colorize(
                '▼ {}'.format(difference),
                AnsiColor.RED,
            )
            difference_string = '{:>22s}'.format(difference_string)
        else:
            difference_string = '{:>10s}'.format('-')

        print(
            '{:<25s}{:^20s}{}'.format(
                name,
                time_string,
                difference_string,
            ),
        )
    else:
        print('{:<25s}{:>20s}'.format(name, time_string))


if __name__ == '__main__':
    main()
