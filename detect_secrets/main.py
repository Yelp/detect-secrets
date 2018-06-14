#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function

import json
import sys

from detect_secrets.core import baseline
from detect_secrets.core.log import CustomLog
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins import initialize_plugins


def parse_args(argv):
    return ParserBuilder().add_console_use_arguments() \
        .parse_args(argv)


def main(argv=None):
    if len(sys.argv) == 1:  # pragma: no cover
        sys.argv.append('-h')

    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        CustomLog.enableDebug(args.verbose)

    plugins = initialize_plugins(args.plugins)

    if args.scan:
        if args.exclude:
            args.exclude = args.exclude[0]

        print(
            json.dumps(
                baseline.initialize(
                    plugins,
                    args.exclude,
                    args.scan
                ).format_for_baseline_output(),
                indent=2,
                sort_keys=True
            )
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
