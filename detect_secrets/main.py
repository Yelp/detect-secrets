#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function

import json
import sys

from detect_secrets.core.baseline import initialize
from detect_secrets.core.log import CustomLog
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyDetector


def parse_args(argv):
    return ParserBuilder().add_initialize_baseline_argument() \
        .parse_args(argv)


def main(argv=None):
    if len(sys.argv) == 1:  # pragma: no cover
        sys.argv.append('-h')

    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        CustomLog.enableDebug(args.verbose)

    default_plugins = (
        HexHighEntropyString(args.hex_limit[0]),
        Base64HighEntropyString(args.base64_limit[0]),
        PrivateKeyDetector(),
    )

    if args.scan:
        if args.exclude:
            args.exclude = args.exclude[0]

        print(
            json.dumps(
                initialize(
                    default_plugins,
                    args.exclude,
                    args.scan
                ).format_for_baseline_output(),
                indent=2,
            )
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
