from __future__ import absolute_import

import sys

from detect_secrets.core.baseline import apply_baseline_filter
from detect_secrets.core.log import CustomLog
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.private_key import PrivateKeyPlugin


def parse_args(argv):
    return ParserBuilder().add_filenames_argument() \
        .add_set_baseline_argument() \
        .parse_args(argv)


def pretty_print_diagnostics(secrets):
    """Prints a helpful error message, for better usability.

    :param secrets: SecretsCollection
    """
    log = CustomLog(formatter='%(message)s').getLogger()
    log.error(
        'Potential secrets about to be committed to git repo! Please rectify or\n'
        'explicitly ignore with `pragma: whitelist secret` comment.\n'
    )

    for filename in secrets.data:
        for secret in secrets.data[filename].values():
            log.error(secret)

    log.error(
        'Possible mitigations:\n'
        ' - For information about putting your secrets in a safer place, please ask in #security\n'
        ' - Mark false positives with `# pragma: whitelist secret`\n'
        ' - Use `--no-verify` if this is a one-time false positive\n'
    )

    log.error(
        'If a secret has already been committed, visit '
        'https://help.github.com/articles/removing-sensitive-data-from-a-repository/\n'
    )


def main(argv=None):
    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        CustomLog.enableDebug(args.verbose)

    if args.baseline[0]:
        # If baseline is provided, we first want to make sure it's valid, before
        # doing any further computation.
        try:
            baseline_collection = SecretsCollection.load_from_file(
                args.baseline[0]
            )
        except IOError:
            # Error logs handled in load_from_file logic.
            return 1

    default_plugins = (
        HexHighEntropyString(args.hex_limit[0]),
        Base64HighEntropyString(args.base64_limit[0]),
        PrivateKeyPlugin(),
    )
    collection = SecretsCollection(default_plugins)

    for filename in args.filenames:
        if filename == args.baseline[0]:
            # Obviously, don't detect the baseline file
            continue

        collection.scan_file(filename)

    results = collection
    if args.baseline[0]:
        results = apply_baseline_filter(
            collection,
            baseline_collection,
            args.filenames
        )

    if len(results.data) > 0:
        pretty_print_diagnostics(results)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
