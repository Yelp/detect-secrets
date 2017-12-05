#!/usr/bin/python
from __future__ import absolute_import

import unittest

from detect_secrets.core.baseline import apply_baseline_filter
from detect_secrets.core.baseline import initialize
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString


def add_secret(collection, filename, lineno, secret):
    """Utility function to add individual secrets to a SecretCollection.

    :param collection: SecretCollection; will be modified by this function.
    :param filename:   string
    :param secret:     string; secret to add
    :param lineno:     integer; line number of occurring secret
    """
    if filename not in collection.data:  # pragma: no cover
        collection[filename] = {}

    tmp_secret = PotentialSecret('type', filename, lineno, secret)
    collection.data[filename][tmp_secret] = tmp_secret


class BaselineTest(unittest.TestCase):

    def test_apply_baseline_filter_nothing_new(self):
        new_findings = SecretsCollection()
        baseline = SecretsCollection()

        for collection in [new_findings, baseline]:
            add_secret(collection, 'filename', 1, 'asdf')

        results = apply_baseline_filter(new_findings, baseline, ['filename'])

        # No expected results, because everything filtered out by baseline
        assert len(results.data) == 0

        # Make sure that baseline didn't get modified either
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 1

    def test_apply_baseline_filter_new_file(self):
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename1', 1, 'asdf')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename2', 1, 'asdf')

        backup_baseline = baseline.data.copy()
        results = apply_baseline_filter(new_findings, baseline, ['filename1', 'filename2'])

        assert len(results.data) == 1
        assert 'filename1' in results.data
        assert baseline.data == backup_baseline

    def test_apply_baseline_filter_new_file_excluded(self):
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename1', 1, 'asdf')
        add_secret(new_findings, 'filename2', 1, 'asdf')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename3', 1, 'asdf')

        backup_baseline = baseline.data.copy()
        baseline.exclude_regex = 'filename1'
        results = apply_baseline_filter(new_findings, baseline, ['filename1', 'filename2'])

        assert len(results.data) == 1
        assert 'filename1' not in results.data
        assert baseline.data == backup_baseline

    def test_apply_baseline_filter_new_secret_line_old_file(self):
        """Same file, new line with potential secret"""
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename', 1, 'secret1')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename', 2, 'secret2')

        backup_baseline = baseline.data.copy()
        results = apply_baseline_filter(new_findings, baseline, ['filename'])

        assert len(results.data['filename']) == 1
        secretA = PotentialSecret('type', 'filename', 1, 'secret1')
        assert results.data['filename'][secretA].secret_hash == PotentialSecret.hash_secret('secret1')
        assert baseline.data == backup_baseline

    def test_apply_baseline_filter_rolled_creds(self):
        """Same line, different secret"""
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename', 1, 'secret_new')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename', 1, 'secret')

        backup_baseline = baseline.data.copy()
        results = apply_baseline_filter(new_findings, baseline, ['filename'])

        assert len(results.data['filename']) == 1

        secretA = PotentialSecret('type', 'filename', 1, 'secret_new')
        assert results.data['filename'][secretA].secret_hash == PotentialSecret.hash_secret('secret_new')
        assert baseline.data == backup_baseline

    def test_apply_baseline_filter_deleted_secret(self):
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename', 2, 'tofu')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename', 1, 'hotdog')
        add_secret(baseline, 'filename', 2, 'tofu')

        results = apply_baseline_filter(new_findings, baseline, ['filename'])

        # Since hotdog doesn't appear in new_findings, it should be removed.
        assert len(results.data) == 0
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 2

    def test_apply_baseline_filter_deleted_secret_file(self):
        new_findings = SecretsCollection()
        baseline = SecretsCollection()
        add_secret(baseline, 'filename', 1, 'secret')

        results = apply_baseline_filter(new_findings, baseline, ['filename', 'non_relevant_file'])

        # No results, but baseline should be modified.
        assert len(results.data) == 0
        assert len(baseline.data) == 0

    def test_apply_baseline_filter_same_secret_new_location(self):
        new_findings = SecretsCollection()
        add_secret(new_findings, 'filename', 1, 'secret')

        baseline = SecretsCollection()
        add_secret(baseline, 'filename', 2, 'secret')

        results = apply_baseline_filter(new_findings, baseline, ['filename'])

        # No results, but baseline should be modified with new line location.
        assert len(results.data) == 0
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 1

    def test_initialize_basic_usage(self):
        results = initialize(
            [
                Base64HighEntropyString(4.5),
                HexHighEntropyString(3)
            ],
            rootdir='./test_data',
        ).json()

        assert len(results.keys()) == 3
        assert len(results['file_with_secrets.py']) == 1
        assert len(results['tmp/file_with_secrets.py']) == 2

    def test_initialize_exclude_regex(self):
        results = initialize(
            [
                Base64HighEntropyString(4.5),
                HexHighEntropyString(3)
            ],
            exclude_regex='tmp*',
            rootdir='./test_data',
        ).json()

        assert len(results.keys()) == 2
        assert 'file_with_secrets.py' in results

    def test_initialize_exclude_regex_at_root_level(self):
        results = initialize(
            [
                Base64HighEntropyString(4.5),
                HexHighEntropyString(3)
            ],
            exclude_regex='file_with_secrets.py',
            rootdir='./test_data'
        ).json()

        # All files_with_secrets.py should be ignored, both at the root
        # level, and the nested file in tmp.
        assert len(results.keys()) == 1

    def test_initialize_relative_paths(self):
        results = initialize(
            [
                Base64HighEntropyString(4.5),
                HexHighEntropyString(3)
            ],
            rootdir='test_data/../test_data/tmp/..'
        ).json()

        assert len(results.keys()) == 3
        assert len(results['file_with_secrets.py']) == 1
        assert len(results['tmp/file_with_secrets.py']) == 2
