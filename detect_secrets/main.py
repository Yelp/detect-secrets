#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function

import json
import sys

from detect_secrets.core import audit
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.core import initialize


def parse_args(argv):
    return ParserBuilder().add_console_use_arguments() \
        .parse_args(argv)


def main(argv=None):
    if len(sys.argv) == 1:  # pragma: no cover
        sys.argv.append('-h')

    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        log.set_debug_level(args.verbose)

    if args.action == 'scan':
        output = json.dumps(
            _perform_scan(args),
            indent=2,
            sort_keys=True,
        )

        if args.import_filename:
            _write_to_file(args.import_filename[0], output)
        else:
            print(output)

    elif args.action == 'audit':
        audit.audit_baseline(args.filename[0])

    return 0


def _perform_scan(args):
    old_baseline = _get_existing_baseline(args.import_filename)

    # Plugins are *always* rescanned with fresh settings, because
    # we want to get the latest updates.
    plugins = initialize.from_parser_builder(args.plugins)

    # Favors --exclude argument over existing baseline's regex (if exists)
    if args.exclude:
        args.exclude = args.exclude[0]
    elif old_baseline and old_baseline.get('exclude_regex'):
        args.exclude = old_baseline['exclude_regex']

    # If we have knowledge of an existing baseline file, we should use
    # that knowledge and *not* scan that file.
    if args.import_filename and args.exclude:
        args.exclude += r'|^{}$'.format(args.import_filename[0])

    new_baseline = baseline.initialize(
        plugins,
        args.exclude,
        args.path,
        args.all_files,
    ).format_for_baseline_output()

    if old_baseline:
        new_baseline = baseline.merge_baseline(
            old_baseline,
            new_baseline,
        )

    return new_baseline


def _get_existing_baseline(import_filename):
    # Favors --import argument over stdin.
    if import_filename:
        return _read_from_file(import_filename[0])
    if not sys.stdin.isatty():
        return json.loads(sys.stdin.read())


def _read_from_file(filename):
    """Used for mocking."""
    with open(filename[0]) as f:
        return json.loads(f.read())


def _write_to_file(filename, content):
    """Used for mocking."""
    with open(filename, 'w') as f:
        f.write(content)


if __name__ == '__main__':
    sys.exit(main())
