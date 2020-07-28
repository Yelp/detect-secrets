import json
import textwrap
from contextlib import contextmanager

import mock
import pytest

from detect_secrets import main as main_module
from detect_secrets import VERSION
from detect_secrets.core import audit as audit_module
from detect_secrets.plugins.common.util import import_plugins
from testing.factories import secrets_collection_factory
from testing.mocks import Any
from testing.mocks import mock_printer
from testing.util import uncolor
from testing.util import wrap_detect_secrets_main


def get_list_of_plugins(include=None, exclude=None):
    """
    :type include: List[Dict[str, Any]]
    :type exclude: Iterable[str]
    :rtype: List[Dict[str, Any]]
    """
    included_plugins = []
    if include:
        included_plugins = [
            config['name']
            for config in include
        ]

    output = []
    for name, plugin in import_plugins(custom_plugin_paths=()).items():
        if (
            name in included_plugins or
            exclude and name in exclude
        ):
            continue

        payload = {
            'name': name,
        }
        payload.update(plugin.default_options)

        output.append(payload)

    if include:
        output.extend(include)

    return sorted(output, key=lambda plugin: plugin['name'])


def get_plugin_report(extra=None):
    """
    :type extra: Dict[str, str]
    """
    if not extra:  # pragma: no cover
        extra = {}

    longest_name_length = max([
        len(name)
        for name in import_plugins(custom_plugin_paths=())
    ])

    return '\n'.join(
        sorted([
            '{name}: {result}'.format(
                name=name + ' ' * (longest_name_length - len(name)),
                result='False' if name not in extra else extra[name],
            )
            for name in import_plugins(custom_plugin_paths=())
        ]),
    ) + '\n'


class TestMain:
    """These are smoke tests for the console usage of detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def test_scan_basic(self, mock_baseline_initialize):
        with mock_stdin():
            assert wrap_detect_secrets_main('scan') == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            custom_plugin_paths=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path='.',
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        with mock_stdin():
            assert wrap_detect_secrets_main('scan test_data') == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            custom_plugin_paths=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path=['test_data'],
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_scan_with_exclude_args(self, mock_baseline_initialize):
        with mock_stdin():
            assert wrap_detect_secrets_main(
                'scan --exclude-files some_pattern_here --exclude-lines other_patt',
            ) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            custom_plugin_paths=Any(tuple),
            exclude_files_regex='some_pattern_here',
            exclude_lines_regex='other_patt',
            path='.',
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    @pytest.mark.parametrize(
        'string, expected_base64_result, expected_hex_result',
        [
            (
                '012345678ab',
                'False (3.459)',
                'True  (3.459)',
            ),
            (
                'Benign',
                'False (2.252)',
                'False',
            ),
            (
                'key: 012345678ab',
                'False',
                'True  (3.459)',
            ),
        ],
    )
    def test_scan_string_basic(
        self,
        mock_baseline_initialize,
        string,
        expected_base64_result,
        expected_hex_result,
    ):
        with mock_stdin(
            string,
        ), mock_printer(
            main_module,
        ) as printer_shim:
            assert wrap_detect_secrets_main('scan --string') == 0
            assert uncolor(printer_shim.message) == get_plugin_report({
                'Base64HighEntropyString': expected_base64_result,
                'HexHighEntropyString': expected_hex_result,
            })

        mock_baseline_initialize.assert_not_called()

    def test_scan_string_cli_overrides_stdin(self):
        with mock_stdin(
            '012345678ab',
        ), mock_printer(
            main_module,
        ) as printer_shim:
            assert wrap_detect_secrets_main('scan --string 012345') == 0
            assert uncolor(printer_shim.message) == get_plugin_report({
                'Base64HighEntropyString': 'False (2.585)',
                'HexHighEntropyString': 'False (2.121)',
            })

    def test_scan_with_all_files_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert wrap_detect_secrets_main('scan --all-files') == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            custom_plugin_paths=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path='.',
            should_scan_all_files=True,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_reads_from_stdin(self, mock_merge_baseline):
        with mock_stdin(json.dumps({'key': 'value'})):
            assert wrap_detect_secrets_main('scan') == 0

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )

    def test_reads_old_baseline_from_file(self, mock_merge_baseline):
        with mock_stdin(), mock.patch(
            'detect_secrets.main._read_from_file',
            return_value={'key': 'value'},
        ) as m_read, mock.patch(
            'detect_secrets.main.write_baseline_to_file',
        ) as m_write:
            assert wrap_detect_secrets_main('scan --update old_baseline_file') == 0
            assert m_read.call_args[0][0] == 'old_baseline_file'
            assert m_write.call_args[1]['filename'] == 'old_baseline_file'
            assert m_write.call_args[1]['data'] == Any(dict)

        mock_merge_baseline.assert_called_once_with(
            {'key': 'value'},
            Any(dict),
        )

    @pytest.mark.parametrize(
        'exclude_files_arg, expected_regex',
        [
            (
                '',
                '^old_baseline_file$',
            ),
            (
                '--exclude-files "secrets/.*"',
                'secrets/.*|^old_baseline_file$',
            ),
            (
                '--exclude-files "^old_baseline_file$"',
                '^old_baseline_file$',
            ),
        ],
    )
    def test_old_baseline_ignored_with_update_flag(
        self,
        mock_baseline_initialize,
        exclude_files_arg,
        expected_regex,
    ):
        with mock_stdin(), mock.patch(
            'detect_secrets.main._read_from_file',
            return_value={},
        ), mock.patch(
            # We don't want to be creating a file during test
            'detect_secrets.main.write_baseline_to_file',
        ) as file_writer:
            assert wrap_detect_secrets_main(
                'scan --update old_baseline_file {}'.format(
                    exclude_files_arg,
                ),
            ) == 0

            assert (
                file_writer.call_args[1]['data']['exclude']['files']
                == expected_regex
            )

    @pytest.mark.parametrize(
        'plugins_used, plugins_overwriten, plugins_wrote',
        [
            (  # Remove some plugins from baseline
                [
                    {
                        'base64_limit': 4.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--no-base64-string-scan --no-keyword-scan',
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # All plugins
                [
                    {
                        'base64_limit': 1.5,
                        'name': 'Base64HighEntropyString',
                    },
                ],
                '--use-all-plugins',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 1.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                ),
            ),
            (  # Remove some plugins from all plugins
                [
                    {
                        'base64_limit': 4.5,
                        'name': 'Base64HighEntropyString',
                    },
                ],

                '--use-all-plugins --no-base64-string-scan --no-private-key-scan',
                get_list_of_plugins(
                    exclude=(
                        'Base64HighEntropyString',
                        'PrivateKeyDetector',
                    ),
                ),
            ),
            (  # Use same plugin list from baseline
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '',
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Overwrite base limit from CLI
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    }, {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--base64-limit=5.5',
                [
                    {
                        'base64_limit': 5.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Does not overwrite base limit from CLI if baseline not using the plugin
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--base64-limit=4.5',
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Use overwriten option from CLI only when using --use-all-plugins
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--use-all-plugins --base64-limit=5.5 --no-hex-string-scan --no-keyword-scan',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 5.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                    exclude=(
                        'HexHighEntropyString',
                        'KeywordDetector',
                    ),
                ),
            ),
            (  # Use plugin limit from baseline when using --use-all-plugins and no input limit
                [
                    {
                        'base64_limit': 2.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--use-all-plugins --no-hex-string-scan --no-keyword-scan',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 2.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                    exclude=(
                        'HexHighEntropyString',
                        'KeywordDetector',
                    ),
                ),
            ),
        ],
    )
    def test_plugin_from_old_baseline_respected_with_update_flag(
        self,
        mock_baseline_initialize,
        plugins_used, plugins_overwriten, plugins_wrote,
    ):
        with mock_stdin(), mock.patch(
            'detect_secrets.main._read_from_file',
            return_value={
                'plugins_used': plugins_used,
                'results': {},
                'version': VERSION,
                'exclude': {
                    'files': '',
                    'lines': '',
                },
            },
        ), mock.patch(
            # We don't want to be creating a file during test
            'detect_secrets.main.write_baseline_to_file',
        ) as file_writer:
            assert wrap_detect_secrets_main(
                'scan --update old_baseline_file {}'.format(
                    plugins_overwriten,
                ),
            ) == 0

            assert (
                file_writer.call_args[1]['data']['plugins_used']
                ==
                plugins_wrote
            )

    @pytest.mark.parametrize(
        'filename, expected_output',
        [
            (
                'test_data/short_files/first_line.php',
                textwrap.dedent("""
                    1:secret = 'notHighEnoughEntropy'
                    2:skipped_sequential_false_positive = '0123456789a'
                    3:print('second line')
                    4:var = 'third line'
                """)[1:-1],
            ),
            (
                'test_data/short_files/middle_line.yml',
                textwrap.dedent("""
                    1:deploy:
                    2:    user: aaronloo
                    3:    password:
                    4:        secure: thequickbrownfoxjumpsoverthelazydog
                    5:    on:
                    6:        repo: Yelp/detect-secrets
                """)[1:-1],
            ),
            (
                'test_data/short_files/last_line.ini',
                textwrap.dedent("""
                    1:[some section]
                    2:secrets_for_no_one_to_find =
                    3:    hunter2
                    4:    password123
                    5:    BEEF0123456789a
                """)[1:-1],
            ),
        ],
    )
    def test_audit_short_file(self, filename, expected_output):
        with mock_stdin(), mock_printer(
            # To extract the baseline output
            main_module,
        ) as printer_shim:
            wrap_detect_secrets_main('scan ' + filename)
            baseline = printer_shim.message

        baseline_dict = json.loads(baseline)
        baseline_dict['custom_plugin_paths'] = tuple(baseline_dict['custom_plugin_paths'])
        with mock_stdin(), mock.patch(
            # To pipe in printer_shim
            'detect_secrets.core.audit._get_baseline_from_file',
            return_value=baseline_dict,
        ), mock.patch(
            # We don't want to clear the pytest testing screen
            'detect_secrets.core.audit._clear_screen',
        ), mock.patch(
            # Gotta mock it, because tests aren't interactive
            'detect_secrets.core.audit._get_user_decision',
            return_value='s',
        ), mock.patch(
            # We don't want to write an actual file
            'detect_secrets.core.audit.write_baseline_to_file',
        ), mock_printer(
            audit_module,
        ) as printer_shim:
            wrap_detect_secrets_main('audit will_be_mocked')

            assert uncolor(printer_shim.message) == textwrap.dedent("""
                Secret:      1 of 1
                Filename:    {}
                Secret Type: {}
                ----------
                {}
                ----------
                Saving progress...
            """)[1:].format(
                filename,
                baseline_dict['results'][filename][0]['type'],
                expected_output,
            )

    @pytest.mark.parametrize(
        'filename, expected_output',
        [
            (
                'test_data/short_files/first_line.php',
                {
                    'KeywordDetector': {
                        'config': {
                            'name': 'KeywordDetector',
                            'keyword_exclude': None,
                        },
                        'results': {
                            'false-positives': {},
                            'true-positives': {},
                            'unknowns': {
                                'test_data/short_files/first_line.php': [{
                                    'line': "secret = 'notHighEnoughEntropy'",
                                    'plaintext': 'nothighenoughentropy',
                                }],
                            },
                        },
                    },
                },
            ),
        ],
    )
    def test_audit_display_results(self, filename, expected_output):
        with mock_stdin(), mock_printer(
            main_module,
        ) as printer_shim:
            wrap_detect_secrets_main('scan ' + filename)
            baseline = printer_shim.message

        baseline_dict = json.loads(baseline)
        baseline_dict['custom_plugin_paths'] = tuple(baseline_dict['custom_plugin_paths'])
        with mock.patch(
            'detect_secrets.core.audit._get_baseline_from_file',
            return_value=baseline_dict,
        ), mock_printer(
            audit_module,
        ) as printer_shim:
            wrap_detect_secrets_main('audit --display-results MOCKED')

            assert json.loads(uncolor(printer_shim.message))['plugins'] == expected_output

    def test_audit_diff_not_enough_files(self):
        assert wrap_detect_secrets_main('audit --diff fileA') == 1

    def test_audit_same_file(self):
        with mock_printer(main_module) as printer_shim:
            assert wrap_detect_secrets_main('audit --diff .secrets.baseline .secrets.baseline') == 0
            assert printer_shim.message.strip() == (
                'No difference, because it\'s the same file!'
            )


@contextmanager
def mock_stdin(response=None):
    if not response:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = True
            yield

    else:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = False
            m.stdin.read.return_value = response
            yield


@pytest.fixture
def mock_baseline_initialize():
    def mock_initialize_function(plugins, exclude_files_regex, *args, **kwargs):
        return secrets_collection_factory(
            plugins=plugins,
            exclude_files_regex=exclude_files_regex,
        )

    with mock.patch(
        'detect_secrets.main.baseline.initialize',
        side_effect=mock_initialize_function,
    ) as mock_initialize:
        yield mock_initialize


@pytest.fixture
def mock_merge_baseline():
    with mock.patch(
        'detect_secrets.main.baseline.merge_baseline',
    ) as m:
        # This return value needs to have the `results` key, so that it can
        # formatted appropriately for output.
        m.return_value = {'results': {}}
        yield m
