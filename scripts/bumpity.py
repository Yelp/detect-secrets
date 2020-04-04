#!/usr/bin/env python3
"""Bumps the detect-secrets version,
in both `detect_secrets/__init__.py` and `README.md`.

Then commits.
"""
import argparse
import pathlib
import subprocess
import sys


PROJECT_ROOT = pathlib.Path(__file__).absolute().parent.parent
INIT_FILE_PATH = PROJECT_ROOT.joinpath('detect_secrets/__init__.py')
README_FILE_PATH = PROJECT_ROOT.joinpath('README.md')


def _argparse_bump_type(value):
    VALID_BUMP_TYPES = ('major', 'minor', 'patch')

    if value in VALID_BUMP_TYPES:
        return value

    raise argparse.ArgumentTypeError(
        f"Argument {value} must be one 'major', 'minor', 'patch'.",
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__,
        prog='bumpity',
    )
    parser.add_argument(
        '--bump',
        help='the bump type, specified as one of {major, minor, patch}',
        metavar='{major,minor,patch}',
        type=_argparse_bump_type,
    )

    return parser.parse_args(argv)


def get_current_version():
    with open(INIT_FILE_PATH) as init_file:
        first_line = init_file.read().splitlines()[0]
    # e.g. VERSION = '0.13.0'
    _, semver = first_line.replace(' ', '').split('=')
    return map(
        int,
        # e.g. '0.13.0'
        semver.strip("'").split('.'),
    )


def update_init_file(new_version):
    with open(INIT_FILE_PATH, 'w') as init_file:
        init_file.write(f"VERSION = '{new_version}'\n")


def update_readme(old_version, new_version):
    with open(README_FILE_PATH, 'r') as readme:
        original_text = readme.read()
    with open(README_FILE_PATH, 'w') as readme:
        readme.write(
            original_text.replace(old_version, new_version),
        )


def stage_and_commit(new_version):
    # Stage files
    subprocess.check_output(
        (
            'git',
            'add',
            INIT_FILE_PATH,
            README_FILE_PATH,
        ),
    )

    # Check they are the only ones staged
    staged_files = subprocess.check_output(
        (
            'git',
            'diff',
            '--staged',
            '--name-only',
        ),
    ).splitlines()
    if len(staged_files) != 2:
        raise RuntimeWarning('More files staged than __init__.py and README.md')

    # Make the commit
    subprocess.check_output(
        (
            'git',
            'commit',
            '--message',
            f':fist: Bumping version to {new_version}',
            INIT_FILE_PATH,
            README_FILE_PATH,
        ),
    )


def main(argv=sys.argv[1:]):
    if not argv:
        argv.append('--help')
    args = parse_args(argv)

    major, minor, patch = get_current_version()
    old_version = f'{major}.{minor}.{patch}'

    if args.bump == 'major':
        major += 1
        minor = 0
        patch = 0
    elif args.bump == 'minor':
        minor += 1
        patch = 0
    else:
        patch += 1

    new_version = f'{major}.{minor}.{patch}'
    update_init_file(new_version)
    update_readme(old_version, new_version)
    stage_and_commit(new_version)
    print("Don't forget to update CHANGELOG.md too!")


if __name__ == '__main__':
    sys.exit(main())
