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
        # Plugins are *always* rescanned with fresh settings, because
        # we want to get the latest updates.
        plugins = initialize.from_parser_builder(args.plugins)

        if args.string:
            line = args.string
            if isinstance(args.string, bool):
                line = sys.stdin.read().splitlines()[0]

            _scan_string(line, plugins)
            return 0

        print(
            json.dumps(
                _perform_scan(args, plugins),
                indent=2,
                sort_keys=True,
            ),
        )

    elif args.action == 'audit':
        audit.audit_baseline(args.filename[0])

    return 0


def _scan_string(line, plugins):
    longest_plugin_name_length = max(
        map(
            lambda x: len(x.__class__.__name__),
            plugins,
        ),
    )

    output = [
        ('{:%d}: {}' % longest_plugin_name_length).format(
            plugin.__class__.__name__,
            plugin.adhoc_scan(line),
        )
        for plugin in plugins
    ]

    print('\n'.join(sorted(output)))


def _perform_scan(args, plugins):
    old_baseline = _get_existing_baseline(args.import_filename)

    # Favors --exclude argument over existing baseline's regex (if exists)
    if args.exclude:
        args.exclude = args.exclude[0]
    elif old_baseline and old_baseline.get('exclude_regex'):
        args.exclude = old_baseline['exclude_regex']

    new_baseline = baseline.initialize(
        plugins,
        args.exclude,
        args.path,
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
        with open(import_filename[0]) as f:
            return json.loads(f.read())

    if not sys.stdin.isatty():
        return json.loads(sys.stdin.read())


if __name__ == '__main__':
    sys.exit(main())
