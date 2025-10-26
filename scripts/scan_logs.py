#!/usr/bin/env python3
"""Simple wrapper to scan log files line-by-line using detect-secrets' adhoc API.

Usage examples:
  # scan default `log.txt` in repo root and pretty-print results
  python scripts/scan_logs.py

  # scan a specific file and output newline-delimited JSON, showing matched secret values
  python scripts/scan_logs.py /path/to/logfile.log --json --show-secret

  # only enable a specific plugin by class name (e.g. PiiDetector)
  python scripts/scan_logs.py --only PiiDetector
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable

from detect_secrets.core.scan import scan_line
from detect_secrets.settings import transient_settings


def iter_matches_for_file(path: str) -> Iterable[dict]:
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for lineno, line in enumerate(fh, start=1):
            for secret in scan_line(line):
                yield {
                    'file': path,
                    'line_number': lineno,
                    'type': secret.type,
                    'hashed_secret': secret.secret_hash,
                    'secret_value': secret.secret_value,
                }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Scan log files for secrets/PII using detect-secrets')
    parser.add_argument('path', nargs='?', default='log.txt', help='Path to log file (default: log.txt)')
    parser.add_argument('--only', action='append', dest='only_plugins', help='Only enable these plugin class names (repeatable)')
    parser.add_argument('--json', action='store_true', dest='as_json', help='Print newline-delimited JSON for each match')
    parser.add_argument('--show-secret', action='store_true', dest='show_secret', help='Include plaintext secret_value in output (off by default)')
    parser.add_argument('--encoding', default='utf-8', help='File encoding (default: utf-8)')

    args = parser.parse_args(argv)

    # If user asked to limit plugins, use transient_settings to restrict plugins to only those names.
    if args.only_plugins:
        plugins_cfg = [{'name': name} for name in args.only_plugins]
        settings_ctx = transient_settings({'plugins_used': plugins_cfg})
    else:
        # contextmanager that does nothing (transient_settings requires an arg), so use a dummy one
        settings_ctx = transient_settings({'plugins_used': []}) if False else None

    try:
        if settings_ctx is not None:
            settings_ctx.__enter__()

        # Stream and print
        for match in iter_matches_for_file(args.path):
            out = {
                'file': match['file'],
                'line_number': match['line_number'],
                'type': match['type'],
                'hashed_secret': match['hashed_secret'],
            }
            if args.show_secret:
                out['secret_value'] = match['secret_value']

            if args.as_json:
                print(json.dumps(out, ensure_ascii=False))
            else:
                # Pretty print
                secret_display = out.get('secret_value', '<hidden>') if args.show_secret else '<hidden>'
                print(f"{out['file']}:{out['line_number']} [{out['type']}] {secret_display}")

    finally:
        if settings_ctx is not None:
            settings_ctx.__exit__(None, None, None)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
