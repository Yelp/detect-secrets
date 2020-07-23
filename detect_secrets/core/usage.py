import argparse
import os
from collections import namedtuple
from functools import lru_cache

from detect_secrets import VERSION
from detect_secrets.plugins.common.util import import_plugins


def add_exclude_lines_argument(parser):
    parser.add_argument(
        '--exclude-lines',
        type=str,
        help='Pass in regex to specify lines to ignore during scan.',
    )


def add_word_list_argument(parser):
    parser.add_argument(
        '--word-list',
        type=str,
        help=(
            'Text file with a list of words, '
            'if a secret contains a word in the list we ignore it.'
        ),
        dest='word_list_file',
    )


def _is_valid_path(path):  # pragma: no cover
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(
            'Invalid path: {}'.format(path),
        )

    return path


class TupleAction(argparse.Action):
    def __call__(self, parser, namespace, values, options_string=None):
        existing_values = getattr(
            namespace,
            self.dest,
        )
        setattr(
            namespace,
            self.dest,
            existing_values + (values,),
        )


def add_custom_plugins_argument(parser):
    """
    We turn custom_plugins_paths into a tuple so that we can
    @lru_cache all the functions that take it as an argument.
    """
    parser.add_argument(
        '--custom-plugins',
        action=TupleAction,
        default=(),
        dest='custom_plugin_paths',
        help=(
            'Custom plugin Python files, or directories containing them. '
            'Directories are not searched recursively.'
        ),
        type=_is_valid_path,
    )


def add_use_all_plugins_argument(parser):
    parser.add_argument(
        '--use-all-plugins',
        action='store_true',
        help='Use all available plugins to scan files.',
    )


def add_no_verify_flag(parser):
    parser.add_argument(
        '-n',
        '--no-verify',
        action='store_true',
        help='Disables additional verification of secrets via network call.',
    )


def add_shared_arguments(parser):
    """
    These are arguments that are for both
    `detect-secrets-hook` and `detect-secrets` console scripts.
    """
    add_exclude_lines_argument(parser)
    add_word_list_argument(parser)
    add_custom_plugins_argument(parser)
    add_use_all_plugins_argument(parser)
    add_no_verify_flag(parser)


def get_parser_to_add_opt_out_options_to(parser):
    """
    The pre-commit hook gets e.g. `--no-jwt-scan` type options
    as well as the subparser for `detect-secrets scan`.

    :rtype: argparse.ArgumentParser
    :returns: argparse.ArgumentParser to pass into PluginOptions
    """
    for action in parser._actions:  # pragma: no cover (Always returns)
        if isinstance(action, argparse._SubParsersAction):
            for subparser in action.choices.values():
                if subparser.prog.endswith('scan'):
                    return subparser
    # Assume it is the 'detect-secrets-hook' console script
    # Relying on parser.prog is too brittle
    return parser


class ParserBuilder:

    def __init__(self):
        self.parser = argparse.ArgumentParser()

        self.add_default_arguments()

    def add_default_arguments(self):
        self._add_verbosity_argument()\
            ._add_version_argument()

    def add_pre_commit_arguments(self):
        self._add_filenames_argument()\
            ._add_set_baseline_argument()\

        add_shared_arguments(self.parser)

        PluginOptions(self.parser).add_arguments()

        return self

    def add_console_use_arguments(self):
        subparser = self.parser.add_subparsers(
            dest='action',
        )

        for action_parser in (ScanOptions, AuditOptions):
            action_parser(subparser).add_arguments()

        return self

    def parse_args(self, argv):
        # We temporarily remove '--help' so that we can give the full
        # amount of options (e.g. --no-custom-detector) after loading
        # custom plugins.
        argv_without_help = list(
            filter(
                lambda arg: (
                    arg not in ('-h', '--help')
                ),
                argv,
            ),
        )

        known_args, _ = self.parser.parse_known_args(
            args=argv_without_help,
        )

        # Audit does not use the `--custom-plugins` argument
        # It pulls custom_plugins from the audited baseline
        if hasattr(known_args, 'custom_plugin_paths'):
            # Add e.g. `--no-jwt-scan` type options
            # now that we can use the --custom-plugins argument
            PluginOptions(
                get_parser_to_add_opt_out_options_to(self.parser),
            ).add_opt_out_options(
                known_args.custom_plugin_paths,
            )

        args = self.parser.parse_args(
            args=argv,
        )
        PluginOptions.consolidate_args(args)

        return args

    def _add_version_argument(self):
        self.parser.add_argument(
            '--version',
            action='version',
            version=VERSION,
            help='Display version information.',
        )
        return self

    def _add_verbosity_argument(self):
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='count',
            help='Verbose mode.',
        )
        return self

    def _add_filenames_argument(self):
        self.parser.add_argument(
            'filenames',
            nargs='*',
            help='Filenames to check.',
        )
        return self

    def _add_set_baseline_argument(self):
        self.parser.add_argument(
            '--baseline',
            nargs=1,
            default=[''],
            help='Sets a baseline for explicitly ignored secrets, generated by `--scan`.',
        )
        return self


class ScanOptions:

    def __init__(self, subparser):
        self.parser = subparser.add_parser(
            'scan',
        )

    def add_arguments(self):
        self._add_initialize_baseline_argument()\
            ._add_adhoc_scanning_argument()

        PluginOptions(self.parser).add_arguments()

        return self

    def _add_initialize_baseline_argument(self):
        self.parser.add_argument(
            'path',
            nargs='*',
            default='.',
            help=(
                'Scans the entire codebase and outputs a snapshot of '
                'currently identified secrets.'
            ),
        )

        add_shared_arguments(self.parser)

        # Pairing `--exclude-files` with `--scan` because it's only used for the initialization.
        # The pre-commit hook framework already has an `exclude` option that can
        # be used instead.
        self.parser.add_argument(
            '--exclude-files',
            type=str,
            help='Pass in regex to specify ignored paths during initialization scan.',
        )

        # Pairing `--update` with `--scan` because it's only used for
        # initialization.
        self.parser.add_argument(
            '--update',
            nargs=1,
            metavar='OLD_BASELINE_FILE',
            help='Update existing baseline by importing settings from it.',
            dest='import_filename',
        )

        self.parser.add_argument(
            '--all-files',
            action='store_true',
            help='Scan all files recursively (as compared to only scanning git tracked files).',
        )

        return self

    def _add_adhoc_scanning_argument(self):
        self.parser.add_argument(
            '--string',
            nargs='?',
            const=True,
            help=(
                'Scans an individual string, and displays configured '
                'plugins\' verdict.'
            ),
        )


class AuditOptions:

    def __init__(self, subparser):
        self.parser = subparser.add_parser(
            'audit',
        )

    def add_arguments(self):
        self.parser.add_argument(
            'filename',
            nargs='+',
            help=(
                'Audit a given baseline file to distinguish the difference '
                'between false and true positives.'
            ),
        )

        action_parser = self.parser.add_mutually_exclusive_group()

        action_parser.add_argument(
            '--diff',
            action='store_true',
            help=(
                'Allows the comparison of two baseline files, in order to '
                'effectively distinguish the difference between various '
                'plugin configurations.'
            ),
        )

        action_parser.add_argument(
            '--display-results',
            action='store_true',
            help=(
                'Displays the results of an interactive auditing session '
                'which have been saved to a baseline file.'
            ),
        )

        return self


class PluginDescriptor(
    namedtuple(
        'PluginDescriptor',
        [
            # Classname of plugin; used for initialization
            'classname',

            # Flag to disable plugin. e.g. `--no-hex-string-scan`
            'disable_flag_text',

            # Description for disable flag.
            'disable_help_text',

            # type: list
            # Allows the bundling of all related command line provided
            # arguments together, under one plugin name.
            # Assumes there is no shared related arg.
            #
            # Furthermore, each related arg can have its own default
            # value (paired together, with a tuple). This allows us to
            # distinguish the difference between a default value, and
            # whether a user has entered the same value as a default value.
            # Therefore, only populate the default value upon consolidation
            # (rather than relying on argparse default).
            'related_args',
        ],
    ),
):
    def __new__(cls, related_args=None, **kwargs):
        return super(PluginDescriptor, cls).__new__(
            cls,
            related_args=related_args or [],
            **kwargs
        )

    @classmethod
    def from_plugin_class(cls, plugin, name):
        """
        :type plugin: Type[TypeVar('Plugin', bound=BasePlugin)]
        :type name: str
        """
        related_args = None
        if plugin.default_options:
            related_args = []
            for arg_name, value in plugin.default_options.items():
                related_args.append((
                    '--{}'.format(arg_name.replace('_', '-')),
                    value,
                ))

        return cls(
            classname=name,
            disable_flag_text='--{}'.format(plugin.disable_flag_text),
            disable_help_text=cls.get_disabled_help_text(plugin),
            related_args=related_args,
        )

    @staticmethod
    def get_disabled_help_text(plugin):
        for line in plugin.__doc__.splitlines():
            line = line.strip().lstrip()
            if line:
                break
        else:
            raise NotImplementedError('Plugins must declare a docstring.')

        line = line[0].lower() + line[1:]
        return 'Disables {}'.format(line)


@lru_cache(maxsize=1)
def get_all_plugin_descriptors(custom_plugin_paths):
    return [
        PluginDescriptor.from_plugin_class(plugin, name)
        for name, plugin in
        import_plugins(custom_plugin_paths).items()
    ]


class PluginOptions:

    def __init__(self, parser):
        self.parser = parser.add_argument_group(
            title='plugins',
            description=(
                'Configure settings for each secret scanning '
                'ruleset. By default, all plugins are enabled '
                'unless explicitly disabled.'
            ),
        )

    def add_arguments(self):
        self._add_custom_limits()
        self._add_keyword_exclude()

        return self

    @staticmethod
    def get_disabled_plugins(args):
        return [
            plugin.classname
            for plugin in get_all_plugin_descriptors(args.custom_plugin_paths)
            if plugin.classname not in args.plugins
        ]

    @staticmethod
    def consolidate_args(args):
        """There are many argument fields related to configuring plugins.
        This function consolidates all of them, and saves the consolidated
        information in args.plugins.

        Note that we're deferring initialization of those plugins, because
        plugins may have various initialization values, referenced in
        different places.

        :param args: output of `argparse.ArgumentParser.parse_args`
        """
        # Using `--hex-limit` as a canary to identify whether this
        # consolidation is appropriate.
        if not hasattr(args, 'hex_limit'):
            return

        active_plugins = {}
        is_using_default_value = {}

        for plugin in get_all_plugin_descriptors(args.custom_plugin_paths):
            arg_name = PluginOptions._convert_flag_text_to_argument_name(
                plugin.disable_flag_text,
            )

            # Remove disabled plugins
            is_disabled = getattr(args, arg_name, False)
            delattr(args, arg_name)
            if is_disabled:
                continue

            # Consolidate related args
            related_args = {}
            for related_arg_tuple in plugin.related_args:
                flag_name, default_value = related_arg_tuple

                arg_name = PluginOptions._convert_flag_text_to_argument_name(
                    flag_name,
                )

                related_args[arg_name] = getattr(args, arg_name)
                delattr(args, arg_name)

                if default_value and related_args[arg_name] is None:
                    related_args[arg_name] = default_value
                    is_using_default_value[arg_name] = True

            active_plugins.update({
                plugin.classname: related_args,
            })

        args.plugins = active_plugins
        args.is_using_default_value = is_using_default_value

    def _add_custom_limits(self):
        high_entropy_help_text = (
            'Sets the entropy limit for high entropy strings. '
            'Value must be between 0.0 and 8.0, '
        )

        self.parser.add_argument(
            '--base64-limit',
            type=self._argparse_minmax_type,
            nargs='?',
            help=high_entropy_help_text + 'defaults to 4.5.',
        )
        self.parser.add_argument(
            '--hex-limit',
            type=self._argparse_minmax_type,
            nargs='?',
            help=high_entropy_help_text + 'defaults to 3.0.',
        )

    def add_opt_out_options(self, custom_plugin_paths):
        for plugin in get_all_plugin_descriptors(custom_plugin_paths):
            self.parser.add_argument(
                plugin.disable_flag_text,
                action='store_true',
                help=plugin.disable_help_text,
                default=False,
            )

    def _argparse_minmax_type(self, string):
        """Custom type for argparse to enforce value limits"""
        value = float(string)
        if value < 0 or value > 8:
            raise argparse.ArgumentTypeError(
                '%s must be between 0.0 and 8.0' % string,
            )

        return value

    @staticmethod
    def _convert_flag_text_to_argument_name(flag_text):
        """This just emulates argparse's underlying logic.

        :type flag_text: str
        :param flag_text: e.g. `--no-hex-string-scan`
        :return: `no_hex_string_scan`
        """
        return flag_text[2:].replace('-', '_')

    def _add_keyword_exclude(self):
        self.parser.add_argument(
            '--keyword-exclude',
            type=str,
            help='Pass in regex to exclude false positives found by keyword detector.',
        )
