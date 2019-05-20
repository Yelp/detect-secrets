#!/usr/bin/python
import argparse
import subprocess

from monotonic import monotonic

from detect_secrets.core.usage import PluginOptions


def get_arguments():
    parser = argparse.ArgumentParser(description='Run some benchmarks.')
    parser.add_argument(
        'rest_args',
        nargs=argparse.REMAINDER,
        help='filenames to check or detect-secrets compatible arguments',
    )
    args = parser.parse_args()
    return ['../.'] if len(args.rest_args) == 0 else args.rest_args


def run_bench(flags, arguments):
    start_time = monotonic()
    subprocess.check_output('detect-secrets scan'.split() + arguments + flags)
    return monotonic() - start_time


def print_line(name, time):
    print('{:<20s}{:>20s}s'.format(name, str(time)))


def main():
    flag_list = list()
    additional_arguments = get_arguments()

    # Fill flags list with PluginOptions flag text
    for flag_number, flag in enumerate(PluginOptions.all_plugins):
        flag_list.append(flag.disable_flag_text)

    # Run bechmarks for all the cases
    for flag_number, flag in enumerate(flag_list):
        temp = list(flag_list)
        temp.pop(flag_number)
        if flag_number == 0:
            print('Scanning: ' + str(additional_arguments))
            print('-' * 42)
            print('{:<20s}{:>20s}'.format('benchmark', 'time'))
            print('-' * 42)
            print_line('all-plugins', run_bench([], additional_arguments))
        print_line(flag[len('--no-'):], run_bench(temp, additional_arguments))


main()
