import random

import mock
import pytest

from detect_secrets.core import baseline
from detect_secrets.core.baseline import format_baseline_for_output
from detect_secrets.core.baseline import get_secrets_not_in_baseline
from detect_secrets.core.baseline import merge_baseline
from detect_secrets.core.baseline import merge_results
from detect_secrets.core.baseline import trim_baseline_of_removed_secrets
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from testing.factories import secrets_collection_factory
from testing.mocks import mock_git_calls
from testing.mocks import mock_open
from testing.mocks import SubprocessMock


class TestInitializeBaseline:

    def setup(self):
        self.plugins = (
            Base64HighEntropyString(4.5),
            HexHighEntropyString(3),
        )

    def get_results(
        self,
        path=['./test_data/files'],
        exclude_files_regex=None,
        scan_all_files=False,
    ):
        return baseline.initialize(
            path,
            self.plugins,
            custom_plugin_paths=(),
            exclude_files_regex=exclude_files_regex,
            should_scan_all_files=scan_all_files,
        ).json()

    @pytest.mark.parametrize(
        'path',
        [
            [
                './test_data/files',

                # Test relative paths
                'test_data/../test_data/files/tmp/..',
            ],
        ],
    )
    def test_basic_usage(self, path):
        results = self.get_results(path=path)

        assert len(results.keys()) == 2
        assert len(results['test_data/files/file_with_secrets.py']) == 1
        assert len(results['test_data/files/tmp/file_with_secrets.py']) == 2

    @pytest.mark.parametrize(
        'path',
        [
            [
                './test_data/files',
            ],
        ],
    )
    def test_error_when_getting_git_tracked_files(self, path):
        with mock_git_calls(
            'detect_secrets.core.baseline.subprocess.check_output',
            (
                SubprocessMock(
                    expected_input='git -C ./test_data/files ls-files',
                    should_throw_exception=True,
                    mocked_output='',
                ),
            ),
        ):
            results = self.get_results(path=['./test_data/files'])

        assert not results

    def test_with_multiple_files(self):
        results = self.get_results(
            path=[
                'test_data/files/file_with_secrets.py',
                'test_data/files/tmp/file_with_secrets.py',
            ],
        )

        assert len(results['test_data/files/file_with_secrets.py']) == 1
        assert len(results['test_data/files/tmp/file_with_secrets.py']) == 2
        assert 'test_data/files/file_with_secrets.py' in results
        assert 'test_data/files/tmp/file_with_secrets.py' in results

    def test_with_multiple_non_existent_files(self):
        with mock.patch(
            'detect_secrets.core.baseline.util.get_relative_path_if_in_cwd',
            return_value=None,
        ):
            results = self.get_results(
                path=[
                    'non-existent-file.A',
                    'non-existent-file.B',
                    # Will be non-existant due to mock.patch
                    'test_data/files/tmp/',
                ],
            )
        # No expected results, because files don't exist
        assert not results

    def test_with_folders_and_files(self):
        results = self.get_results(
            path=[
                'non-existent-file.B',
                'test_data/',
                'test_data/empty_folder',
            ],
        )

        assert 'test_data/files/file_with_secrets.py' in results
        assert 'test_data/files/tmp/file_with_secrets.py' in results
        assert 'test_data/files/file_with_no_secrets.py' not in results
        assert 'non-existent-file.B' not in results

    def test_exclude_regex(self):
        results = self.get_results(exclude_files_regex='tmp*')

        assert len(results.keys()) == 1
        assert 'test_data/files/file_with_secrets.py' in results

    def test_exclude_regex_at_root_level(self):
        results = self.get_results(exclude_files_regex='file_with_secrets.py')

        # All files_with_secrets.py should be ignored, both at the root
        # level, and the nested file in tmp.
        assert not results

    def test_no_files_in_git_repo(self):
        with mock_git_calls(
            'detect_secrets.core.baseline.subprocess.check_output',
            (
                SubprocessMock(
                    expected_input='git ls-files will_be_mocked',
                    should_throw_exception=True,
                    mocked_output='',
                ),
            ),
        ):
            results = self.get_results(path=['will_be_mocked'])

        assert not results

    def test_single_non_tracked_git_file_should_work(self):
        with mock.patch(
            'detect_secrets.core.baseline.os.path.isfile',
            return_value=True,
        ), mock_open(
            'Super hidden value "BEEF0123456789a"',
            'detect_secrets.core.secrets_collection.codecs.open',
        ):
            results = self.get_results(path=['will_be_mocked'])

        assert len(results['will_be_mocked']) == 1

    def test_scan_all_files(self):
        results = self.get_results(
            path=['test_data/files'],
            scan_all_files=True,
        )
        assert len(results.keys()) == 2

    def test_scan_all_files_with_bad_symlinks(self):
        with mock.patch(
            'detect_secrets.core.baseline.util.get_relative_path_if_in_cwd',
            return_value=None,
        ):
            results = self.get_results(
                # Will be non-existant due to mock.patch
                path=['test_data/files'],
                scan_all_files=True,
            )
        assert len(results.keys()) == 0


class TestGetSecretsNotInBaseline:

    def test_nothing_new(self):
        # We want a secret, but just a default secret (no overriding parameters)
        new_findings = secrets_collection_factory([{}])
        baseline = secrets_collection_factory([{}])

        results = get_secrets_not_in_baseline(new_findings, baseline)

        # No expected results, because everything filtered out by baseline
        assert len(results.data) == 0

        # Make sure that baseline didn't get modified either
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 1

    def test_new_file(self):
        new_findings = secrets_collection_factory([
            {
                'filename': 'filename1',
            },
        ])
        baseline = secrets_collection_factory([
            {
                'filename': 'filename2',
            },
        ])

        backup_baseline = baseline.data.copy()
        results = get_secrets_not_in_baseline(new_findings, baseline)

        assert len(results.data) == 1
        assert 'filename1' in results.data
        assert baseline.data == backup_baseline

    def test_new_file_excluded(self):
        new_findings = secrets_collection_factory([
            {
                'filename': 'filename1',
            },
            {
                'filename': 'filename2',
            },
        ])
        baseline = secrets_collection_factory([
            {
                'filename': 'filename3',
            },
        ])

        backup_baseline = baseline.data.copy()
        baseline.exclude_files = 'filename1'
        results = get_secrets_not_in_baseline(new_findings, baseline)

        assert len(results.data) == 1
        assert 'filename1' not in results.data
        assert baseline.data == backup_baseline

    def test_new_secret_line_old_file(self):
        """Same file, new line with potential secret"""
        new_findings = secrets_collection_factory([
            {
                'secret': 'secret1',
                'lineno': 1,
            },
        ])
        baseline = secrets_collection_factory([
            {
                'secret': 'secret2',
                'lineno': 2,
            },
        ])

        backup_baseline = baseline.data.copy()
        results = get_secrets_not_in_baseline(new_findings, baseline)

        assert len(results.data['filename']) == 1
        secretA = PotentialSecret('type', 'filename', 'secret1', 1)
        assert results.data['filename'][secretA].secret_hash == \
            PotentialSecret.hash_secret('secret1')
        assert baseline.data == backup_baseline

    def test_rolled_creds(self):
        """Same line, different secret"""
        new_findings = secrets_collection_factory([
            {
                'secret': 'secret_new',
            },
        ])
        baseline = secrets_collection_factory([
            {
                'secret': 'secret',
            },
        ])

        backup_baseline = baseline.data.copy()
        results = get_secrets_not_in_baseline(new_findings, baseline)

        assert len(results.data['filename']) == 1

        secretA = PotentialSecret('type', 'filename', 'secret_new', 1)
        assert results.data['filename'][secretA].secret_hash == \
            PotentialSecret.hash_secret('secret_new')
        assert baseline.data == backup_baseline


class TestUpdateBaselineWithRemovedSecrets:

    def test_deleted_secret(self):
        new_findings = secrets_collection_factory([
            {
                'secret': 'secret',
                'lineno': 2,
            },
        ])
        baseline = secrets_collection_factory([
            {
                'secret': 'deleted_secret',
                'lineno': 1,
            },
            {
                'secret': 'secret',
                'lineno': 2,
            },
        ])

        is_successful = trim_baseline_of_removed_secrets(
            new_findings,
            baseline,
            ['filename'],
        )

        assert is_successful
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 2

    def test_deleted_secret_file(self):
        new_findings = secrets_collection_factory()
        baseline = secrets_collection_factory([
            {
                'filename': 'filename',
            },
        ])

        is_successful = trim_baseline_of_removed_secrets(
            new_findings,
            baseline,
            [
                # This is in baseline, but not in results, so
                # it should be deleted from baseline.
                'filename',
            ],
        )

        assert is_successful
        assert len(baseline.data) == 0

    def test_same_secret_new_location(self):
        new_findings = secrets_collection_factory([
            {
                'lineno': 1,
            },
        ])
        baseline = secrets_collection_factory([
            {
                'lineno': 2,
            },
        ])

        is_successful = trim_baseline_of_removed_secrets(
            new_findings,
            baseline,
            ['filename'],
        )

        assert is_successful
        assert len(baseline.data) == 1
        assert next(iter(baseline.data['filename'])).lineno == 1

    @pytest.mark.parametrize(
        'results_dict,baseline_dict',
        [
            (
                {},
                {
                    'filename': 'baseline_only_file',
                },
            ),

            # Exact same secret, so no modifications necessary.
            (
                {},
                {},
            ),
        ],
    )
    def test_no_baseline_modifications(self, results_dict, baseline_dict):
        new_findings = secrets_collection_factory([results_dict])
        baseline = secrets_collection_factory([baseline_dict])

        assert not trim_baseline_of_removed_secrets(
            new_findings,
            baseline,
            ['filename'],
        )


class TestMergeBaseline:

    def test_copies_is_secret_label_accurately(self):
        assert merge_baseline(
            {
                'results': {
                    'filenameA': [
                        # Old has label, but new does not.
                        {
                            'hashed_secret': 'a',
                            'is_secret': False,
                            'line_number': 1,
                            'type': 'Test Type',
                        },
                        # Both old and new have label
                        {
                            'hashed_secret': 'b',
                            'is_secret': True,
                            'line_number': 2,
                            'type': 'Test Type',
                        },
                    ],
                    'filenameB': [
                        # Only new has label
                        {
                            'hashed_secret': 'c',
                            'line_number': 3,
                            'type': 'Test Type',
                        },
                        # Both don't have labels
                        {
                            'hashed_secret': 'd',
                            'line_number': 4,
                            'type': 'Test Type',
                        },
                    ],
                },
            },
            {
                'results': {
                    'filenameA': [
                        {
                            'hashed_secret': 'a',
                            'line_number': 1,
                            'type': 'Test Type',
                        },
                        {
                            'hashed_secret': 'b',
                            'is_secret': False,
                            'line_number': 2,
                            'type': 'Test Type',
                        },
                    ],
                    'filenameB': [
                        {
                            'hashed_secret': 'c',
                            'is_secret': False,
                            'line_number': 3,
                            'type': 'Test Type',
                        },
                        {
                            'hashed_secret': 'd',
                            'line_number': 4,
                            'type': 'Test Type',
                        },
                    ],
                },
            },
        ) == {
            'results': {
                'filenameA': [
                    {
                        'hashed_secret': 'a',
                        'is_secret': False,
                        'line_number': 1,
                        'type': 'Test Type',
                    },
                    {
                        'hashed_secret': 'b',
                        'is_secret': False,
                        'line_number': 2,
                        'type': 'Test Type',
                    },
                ],
                'filenameB': [
                    {
                        'hashed_secret': 'c',
                        'is_secret': False,
                        'line_number': 3,
                        'type': 'Test Type',
                    },
                    {
                        'hashed_secret': 'd',
                        'line_number': 4,
                        'type': 'Test Type',
                    },
                ],
            },

        }
        pass


class TestMergeResults:

    def test_new_results_has_nothing(self):
        old_result = {
            'filenameA': [
                self.get_secret(),
            ],
        }

        assert merge_results(old_result, {}) == {}

    def test_old_results_have_diff_type_will_carry_over(self):
        secretA = self.get_secret()
        secretA['type'] = 'different type'
        secretB = self.get_secret()

        assert merge_results(
            {
                'filenameA': [
                    secretA,
                ],
            },
            {
                'filenameA': [
                    secretA,
                    secretB,
                ],
            },
        ) == {
            'filenameA': [
                secretA,
                secretB,
            ],
        }

    def test_old_results_have_subset_of_new_results(self):
        secretA = self.get_secret()
        secretB = self.get_secret()

        modified_secretA = secretA.copy()
        modified_secretA['is_secret'] = True

        assert merge_results(
            {
                'filenameA': [
                    secretA,
                    secretB,
                ],
            },
            {
                'filenameA': [
                    modified_secretA,
                ],
            },
        ) == {
            'filenameA': [
                modified_secretA,
            ],
        }

    def test_old_results_have_shifted_subset(self):
        secretA = self.get_secret()
        secretA['is_secret'] = False

        secretB = self.get_secret()
        secretC = self.get_secret()
        secretD = self.get_secret()

        modified_secretB = secretB.copy()
        modified_secretB['is_secret'] = True
        modified_secretC = secretC.copy()
        modified_secretC['is_secret'] = False

        assert merge_results(
            {
                'filename': [
                    secretA,
                    secretB,
                    secretC,
                    secretD,
                ],
            },
            {
                'filename': [
                    modified_secretB,
                    modified_secretC,
                ],
            },
        ) == {
            'filename': [
                modified_secretB,
                modified_secretC,
            ],
        }

    def test_old_results_completely_overriden(self):
        secretA = self.get_secret()
        secretB = self.get_secret()

        assert merge_results(
            {
                'filenameA': [secretA],
            },
            {
                'filenameA': [secretB],
            },
        ) == {
            'filenameA': [secretB],
        }

    @staticmethod
    def get_secret():
        """Generates a random secret, used for testing.

        :rtype: dict
        """
        random_number = random.randint(0, 500)
        return {
            'hashed_secret': PotentialSecret.hash_secret(str(random_number)),
            'line_number': random_number,
            'type': 'Test Type',
        }


class TestFormatBaselineForOutput:

    def test_sorts_by_line_number_then_hash_then_type(self):
        output_string = format_baseline_for_output({
            'results': {
                'filename': [
                    # Output order is reverse of this
                    {
                        'hashed_secret': 'f',
                        'line_number': 3,
                        'type': 'LetterDetector',
                    },
                    {
                        'hashed_secret': 'a',
                        'line_number': 3,
                        'type': 'LetterDetector',
                    },
                    {
                        'hashed_secret': 'a',
                        'line_number': 3,
                        'type': 'DifferentDetector',
                    },
                    {
                        'hashed_secret': 'z',
                        'line_number': 2,
                        'type': 'LetterDetector',
                    },
                ],
            },
        })
        assert ''.join(output_string.split()) == ''.join(
            """
                {
                  "results": {
                    "filename": [
                      {
                        "hashed_secret": "z",
                        "line_number": 2,
                        "type": "LetterDetector"
                      },
                      {
                        "hashed_secret": "a",
                        "line_number": 3,
                        "type": "DifferentDetector"
                      },
                      {
                        "hashed_secret": "a",
                        "line_number": 3,
                        "type": "LetterDetector"
                      },
                      {
                        "hashed_secret": "f",
                        "line_number": 3,
                        "type": "LetterDetector"
                      }
                    ]
                  }
                }
            """.split(),
        )
