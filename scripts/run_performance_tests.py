import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
from enum import Enum

from detect_secrets.util import get_root_directory


class TestCase(Enum):
    LONG_FILE = 1
    LONG_LINES = 2


def main():
    args = parse_args()

    # Get data from baseline
    if args.baseline:
        config = args.baseline['config']
        args.mode = config['mode']
        args.length = config['length']

    mode = None
    for case in TestCase:
        if case.name == args.mode:
            mode = case
            break

    content = generate_test_content(
        mode,
        timeout=args.harakiri,
        length=args.length,
    )
    output = scan_content(
        content,
        timeout=args.harakiri,
        baseline=args.baseline,
    )

    if not args.baseline:
        temp = json.loads(output)
        temp['config'] = {
            'mode': mode.name,
            'length': args.length,
        }

        output = json.dumps(temp)

    print(output)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--harakiri',
        default=30,
        type=assert_positive(float),
        help=(
            'Specifies an upper bound for number of seconds to wait for '
            'each test.'
        ),
    )
    parser.add_argument(
        '--baseline',
        type=assert_valid_file,
        help=(
            'Specifies test config file to run. If this is provided, '
            'all config options will be referenced from this file.'
        ),
    )
    parser.add_argument(
        '-m',
        '--mode',
        choices=[
            value.name
            for value in TestCase
        ],
        required=True,
        help='Specifies the type of content to generate.',
    )
    parser.add_argument(
        '-L',
        '--length',
        type=assert_positive(int),
        help='Length of test case content.',
    )

    return parser.parse_args()


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


def generate_test_content(mode, **kwargs):
    """
    :type mode: TestCase
    :type length: int
    :type timeout: float
    """
    if not kwargs['length']:
        del kwargs['length']

    print('Generating content...', file=sys.stderr)
    if mode == TestCase.LONG_FILE:
        return generate_long_file(**kwargs)
    elif mode == TestCase.LONG_LINES:
        return generate_long_lines(**kwargs)


def scan_content(content, timeout, baseline=None):
    """
    :type content: str
    :type timeout: float
    :type baseline: dict|None
    """
    args = [
        'python',
        os.path.join(
            get_root_directory(),
            'scripts/benchmark.py',
        ),
        '--harakiri', str(timeout),
    ]

    with tempfile.NamedTemporaryFile('w') as f:
        f.write(content)

        print('Running checks...', file=sys.stderr)
        if not baseline:
            args.append(f.name)
            return subprocess.check_output(
                args,
                stderr=subprocess.DEVNULL,
            ).decode('utf-8')

        with tempfile.NamedTemporaryFile('w') as b:
            b.write(
                json.dumps({
                    'filenames': [f.name],
                    'timings': baseline['timings'],
                }),
            )
            b.seek(0)

            args.append('--baseline')
            args.append(b.name)

            return subprocess.check_output(
                args,
                stderr=subprocess.DEVNULL,
            ).decode('utf-8')


def generate_long_file(length=250000, **kwargs):
    return generate_content(
        separator='\n',
        length=length,
    )


def generate_long_lines(length=250000, **kwargs):
    return generate_content(
        separator=' ',
        length=length,
    )


def generate_content(separator, length):
    """
    :type secret: str
    :type separator: str
    :type length: int
    """
    valid_secrets = {
        'AWSKeyDetector': 'AKIATESTTESTTESTTEST',
        'ArtifactoryDetector': ':AKCtestTESTte',
        'Base64HighEntropyString': 'Y29uZ3JhdHVsYXRpb25zISB0aGlzIGlzIGEgaGlkZGVuIG1lc3NhZ2U=',
        'BasicAuthDetector': 'http://username:password@example.com',
        'HexHighEntropyString': '123456abcd',
        'KeywordDetector': 'api_key = foobar',
        'MailchimpDetector': '376a2953ed38c31a43ea46e2b19257db-us2',
        'PrivateKeyDetector': 'BEGIN PRIVATE KEY',
        'SlackDetector': 'xoxb-1-test',
        'StripeDetector': 'rk_live_TESTtestTESTtestTESTtest',
    }

    with open(
        os.path.join(
            get_root_directory(),
            'test_data/performance/best-songs.txt',
        ),
    ) as f:
        source_material = f.read().splitlines()

    indexes = {}
    for key in valid_secrets:
        index = random.randint(0, length - 1)
        indexes[index] = key

    content = []
    for line_number in range(length):
        if line_number in indexes:
            content.append(valid_secrets[indexes[line_number]])
        else:
            random_line = random.randint(0, len(source_material) - 1)
            content.append(source_material[random_line])

    return separator.join(content)


if __name__ == '__main__':
    main()
