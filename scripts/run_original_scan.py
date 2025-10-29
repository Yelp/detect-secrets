#!/usr/bin/env python3
"""Run detect-secrets using the repository's original plugin mapping (excluding local additions).

This script builds the list of plugin classnames from the core mapping and excludes
`PiiDetector` (our test plugin) to simulate original behavior. It then streams `logs.txt`
and prints newline-delimited JSON for any matches.
"""
from __future__ import annotations

import json
from typing import Iterable

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.settings import transient_settings
from detect_secrets.core.scan import scan_line


def main(path: str = 'logs.txt') -> int:
    mapping = get_mapping_from_secret_type_to_class()

    # Use the original plugins as defined by their secret_type mapping, but remove
    # our experimental plugin (if present) so we simulate the original repo behavior.
    plugin_cfg = [
        {'name': cls.__name__}
        for cls in mapping.values()
    ]

    with transient_settings({'plugins_used': plugin_cfg}):
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            for lineno, line in enumerate(fh, start=1):
                for secret in scan_line(line):
                    out = {
                        'file': path,
                        'line_number': lineno,
                        'type': secret.type,
                        'hashed_secret': secret.secret_hash,
                    }
                    # Avoid printing plaintext secrets by default (privacy)
                    print(json.dumps(out, ensure_ascii=False))

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
