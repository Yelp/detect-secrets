from __future__ import absolute_import

from detect_secrets.core.usage import ParserBuilder


class ServerParserBuilder(ParserBuilder):
    """Arguments, for the server component"""

    def __init__(self):
        super(ServerParserBuilder, self).__init__()

        self._add_server_arguments()

    def _add_server_arguments(self):
        self._add_initialize_server_argument()\
            ._add_scan_repo_argument()\
            ._add_config_file_argument()\
            ._add_add_repo_argument()\
            ._add_local_repo_flag()\
            ._add_s3_config_file_argument()\
            ._add_set_baseline_argument()

    def _add_initialize_server_argument(self):
        self.parser.add_argument(
            '--initialize',
            nargs='?',
            const='repos.yaml',
            help='Initializes tracked repositories based on a supplied repos.yaml.',
            metavar='CUSTOM_REPO_CONFIG_FILE',
        )

        return self

    def _add_scan_repo_argument(self):
        self.parser.add_argument(
            '--scan-repo',
            nargs=1,
            help='Specify the name of the repo (or path, if local) to scan.',
            metavar='REPO_TO_SCAN',
        )

        return self

    def _add_config_file_argument(self):
        self.parser.add_argument(
            '--config-file',
            nargs=1,
            help='Path to a config.yaml which will be used to initialize defaults and plugins.',
        )

        return self

    def _add_add_repo_argument(self):
        self.parser.add_argument(
            '--add-repo',
            nargs=1,
            help=(
                'Enables the addition of individual tracked git repos, without including it in the config file. '
                'Takes in a git URL (or path to repo, if local) as an argument. '
                'Newly tracked repos will store HEAD as the last scanned commit sha. '
                'Also uses config file specified by `--config-file` to initialize default plugins and other settings.'
            ),
            metavar='REPO_TO_ADD'
        )

        return self

    def _add_local_repo_flag(self):
        self.parser.add_argument(
            '-L',
            '--local',
            action='store_true',
            help=(
                'Allows scanner to be pointed to locally stored repos (instead of git cloning). '
                'Use with --scan-repo or --add-repo.'
            ),
        )

        return self

    def _add_s3_config_file_argument(self):
        self.parser.add_argument(
            '--s3-config-file',
            nargs=1,
            help='Specify keys for storing files on Amazon S3.',
            metavar='S3_CONFIG_FILE',
        )

        return self
