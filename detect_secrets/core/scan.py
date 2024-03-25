from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from typing import Any
from typing import cast
from typing import Generator
from typing import Iterable
from typing import List
from typing import Set
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

from ..custom_types import NamedIO
from ..custom_types import SelfAwareCallable
from ..filters.allowlist import is_line_allowlisted
from ..settings import get_filters
from ..settings import get_plugins
from ..settings import get_settings
from ..transformers import get_transformed_file
from ..util import git
from ..util.code_snippet import CodeSnippet
from ..util.code_snippet import get_code_snippet
from ..util.inject import call_function_with_arguments
from ..util.path import get_relative_path
from .log import log
from .potential_secret import PotentialSecret
from detect_secrets.util.filetype import determine_file_type
from detect_secrets.util.filetype import FileType

if TYPE_CHECKING:
    from detect_secrets.plugins.base import BasePlugin

MIN_LINE_LENGTH = int(os.getenv('CHECKOV_MIN_LINE_LENGTH', '5'))
MAX_LINE_LENGTH = int(os.getenv('CHECKOV_MAX_LINE_LENGTH', '100000'))


@lru_cache(maxsize=1)
def read_raw_lines(file_name: str) -> List[str]:
    try:
        with open(file_name) as f:
            return f.readlines()
    except OSError:
        log.debug(f"Can't open file {file_name}")
        return []


def get_files_to_scan(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
) -> Generator[str, None, None]:
    """
    If we specify specific files, we should be able to scan them. This abides by the
    Principle of Least Surprise -- so users don't have to do:

        $ detect-secrets scan test_data/config.env --all-files

    to scan the specific file.

        >>> list(get_files_to_scan('test_data/config.env')) == ['test_data/config.env']

    In a similar way,

        >>> list(get_files_to_scan('test_data/config.env', '.secrets.baseline')) == \
        ...     ['test_data/config.env', '.secrets.baseline']

    If we specify directories, then we should use git tracked files when possible. To
    override this behavior, we can specify `should_scan_all_files=True`, which will force
    the scan for all files.

    See test cases for more details.

    :param root: if not specified, will assume current repository as root.
    """
    if root:
        root = os.path.realpath(root)

    # First, we determine the appropriate filtering mode to be used.
    # If this is True, then it will consider everything to be valid.
    # Otherwise, it will only list the files that are valid.
    valid_paths: Union[bool, Set[str]] = True
    for path in paths:
        # Since this is not a directory, we assume that it is a file proper, and automatically
        # consider it valid.
        if not os.path.isdir(path):
            continue

        if not should_scan_all_files:
            try:
                valid_paths = git.get_tracked_files(git.get_root_directory(root))
            except subprocess.CalledProcessError:
                log.warning('Did not detect git repository. Try scanning all files instead.')
                valid_paths = False

        # Since valid_paths attempts to get *all* tracked files in the repository, we just need
        # to initialize it once.
        break

    if not valid_paths:
        yield from []
        return

    for path in paths:
        iterator = (
            cast(List[Tuple], [(root or os.getcwd(), None, [path])])
            if os.path.isfile(path)
            else os.walk(path)
        )

        for path_root, _, filenames in iterator:
            for filename in filenames:
                relative_path = get_relative_path(
                    root=root or os.getcwd(),
                    path=os.path.join(path_root, filename),
                )
                if not relative_path:
                    # e.g. symbolic links may be pointing outside the root directory
                    continue

                if (
                    valid_paths is True
                    or relative_path in valid_paths
                ):
                    yield relative_path


def scan_line(line: str) -> Generator[PotentialSecret, None, None]:
    """Used for adhoc string scanning."""
    # Disable this, since it doesn't make sense to run this for adhoc usage.
    get_settings().disable_filters(
        'detect_secrets.filters.common.is_invalid_file',
    )
    get_filters.cache_clear()
    context = get_code_snippet(lines=[line], line_number=1)

    yield from (
        secret
        for plugin in get_plugins()
        for secret in _scan_line(
            plugin=plugin,
            filename='adhoc-string-scan',
            line=line,
            line_number=0,
            enable_eager_search=True,
            context=context,
        )
        if not _is_filtered_out(
            required_filter_parameters=['context'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
            context=context,
        )
    )


def scan_file(filename: str) -> Generator[PotentialSecret, None, None]:
    if not get_plugins():  # pragma: no cover
        log.error('No plugins to scan with!')
        return

    if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
        return

    try:
        has_secret = False
        for lines in _get_lines_from_file(filename):
            lines_list = [
                (number, value, False, False)
                for number, value in enumerate(lines, start=1)
            ]
            for secret in _process_line_based_plugins(
                    lines=lines_list,
                    filename=filename,
            ):
                has_secret = True
                yield secret

            if has_secret:
                break
    except OSError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    """
    :raises: ImportError
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _process_line_based_plugins(lines, filename=filename)


def scan_for_allowlisted_secrets_in_file(filename: str) -> Generator[PotentialSecret, None, None]:
    """
    Developers are able to add individual lines to the allowlist using
    `detect_secrets.filters.allowlist.is_line_allowlisted`. However, there are
    times when we want to verify that no *actual* secrets are added to the codebase
    via this feature.

    This scans specifically for these lines, and ignores everything else.
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    if _is_filtered_out(
        required_filter_parameters=['filename'],
        filename=filename,
    ):
        return

    # NOTE: Unlike `scan_file`, we don't ever have to use eager file transformers, since we already
    # know which lines we want to scan.
    try:
        for lines in _get_lines_from_file(filename):
            lines_list = [
                (number, value, False, False)
                for number, value in enumerate(lines, start=1)
            ]
            yield from _scan_for_allowlisted_secrets_in_lines(lines_list, filename)
            break
    except OSError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_for_allowlisted_secrets_in_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    for filename, lines in _get_lines_from_diff(diff):
        yield from _scan_for_allowlisted_secrets_in_lines(lines, filename)


def _scan_for_allowlisted_secrets_in_lines(
        lines: Iterable[Tuple[int, str, bool, bool]],
        filename: str,
) -> Generator[PotentialSecret, None, None]:
    # We control the setting here because it makes more sense than requiring the caller
    # to set this setting before calling this function.
    get_settings().disable_filters('detect_secrets.filters.allowlist.is_line_allowlisted')
    get_filters.cache_clear()

    line_numbers, lines, is_added, is_removed = zip(*lines)
    line_content = [line.rstrip() for line in lines]
    for line_number, line in zip(line_numbers, line_content):
        context = get_code_snippet(line_content, line_number)
        if not is_line_allowlisted(
            filename=filename,
            line=line,
            context=context,
        ):
            continue

        if _is_filtered_out(required_filter_parameters=['line'], filename=filename, line=line):
            continue

        for plugin in get_plugins():
            yield from _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=context,
            )


def _get_lines_from_file(filename: str) -> Generator[List[str], None, None]:
    """
    This attempts to get lines in a given file. If no more lines are needed, the caller
    is responsible for breaking out of this loop.

    :raises: IOError
    :raises: FileNotFoundError
    """
    with open(filename) as f:
        log.info(f'Checking file: {filename}')

        try:
            lines = get_transformed_file(cast(NamedIO, f))
            if not lines:
                lines = f.readlines()
        except UnicodeDecodeError:
            # We flat out ignore binary files
            return

        yield lines

        # If the above lines don't prove to be useful to the caller, try using eager transformers.
        f.seek(0)
        lines = get_transformed_file(cast(NamedIO, f), use_eager_transformers=True)
        if not lines:
            return

        yield lines


def _get_lines_from_diff(diff: str) -> \
        Generator[Tuple[str, List[Tuple[int, str, bool, bool]]], None, None]:
    """
    :raises: ImportError
    """
    # Local imports, so that we don't need to require unidiff for versions of
    # detect-secrets that don't use it.
    from unidiff import PatchSet  # type:ignore[import-untyped]

    patch_set = PatchSet.from_string(diff)
    for patch_file in patch_set:
        filename = patch_file.path
        if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
            continue

        yield (
            filename,
            [
                (
                    line.target_line_no if line.target_line_no
                    else line.source_line_no, line.value, line.is_added, line.is_removed,
                )
                for chunk in patch_file
                # target_lines refers to incoming (new) changes
                for line in list(chunk)
                if line.is_added or line.is_removed
            ],
        )


def _process_line_based_plugins(
    lines: List[Tuple[int, str, bool, bool]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    line_content = [line[1] for line in lines]

    # NOTE: We iterate through lines *then* plugins, because we want to quit early if any of the
    # filters return True.
    index = 0
    for line_number, line, is_added, is_removed in lines:
        line = line.strip()
        index += 1
        if len(line) < MIN_LINE_LENGTH or len(line) > MAX_LINE_LENGTH:
            # skip lines which have too few or too many none whitespace chars
            continue

        if not is_added and not is_removed:
            code_snippet_line_number = line_number
            raw_code_snippet_lines = read_raw_lines(filename)
        else:
            code_snippet_line_number = index
            raw_code_snippet_lines = line_content

        code_snippet = get_code_snippet(
            lines=line_content,
            line_number=code_snippet_line_number,
        )
        raw_code_snippet = get_code_snippet(
            lines=raw_code_snippet_lines,
            line_number=code_snippet_line_number,
        )

        # We apply line-specific filters, and see whether that allows us to quit early.
        if _is_filtered_out(
            required_filter_parameters=['line'],
            filename=filename,
            line=line,
            context=code_snippet,
        ):
            continue

        for plugin in get_plugins():
            for secret in _scan_line(
                    plugin=plugin,
                    filename=filename,
                    line=line,
                    line_number=line_number,
                    context=code_snippet,
                    raw_context=raw_code_snippet,
            ):
                secret.is_removed = is_removed
                secret.is_added = is_added
                if not _is_filtered_out(
                        required_filter_parameters=['context'],
                        filename=secret.filename,
                        secret=secret.secret_value,
                        plugin=plugin,
                        line=line,
                        context=code_snippet,
                ):
                    if determine_file_type(filename) == FileType.YAML and secret.secret_value:
                        # YAML specifically has multi-line string parsing that groups the
                        # different lines as 1.
                        # Calculate actual line number in case of YAML multi-line string
                        actual_line_number = line_number
                        for i, cline in enumerate(raw_code_snippet_lines[actual_line_number - 1:]):
                            if secret.secret_value in cline:
                                actual_line_number += i
                                break
                        secret.line_number = actual_line_number
                    yield secret


def _scan_line(
    plugin: BasePlugin,
    filename: str,
    line: str,
    line_number: int,
    context: CodeSnippet,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    # NOTE: We don't apply filter functions here yet, because we don't have any filters
    # that operate on (filename, line, plugin) without `secret`
    secrets = call_function_with_arguments(
        plugin.analyze_line,
        filename=filename,
        line=line,
        line_number=line_number,
        context=context,
        **kwargs,
    )
    if not secrets:
        return

    yield from (
        secret
        for secret in secrets
        if not _is_filtered_out(
            required_filter_parameters=['secret'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
        )
    )


def _is_filtered_out(required_filter_parameters: Iterable[str], **kwargs: Any) -> bool:
    for filter_fn in get_filters_with_parameter(*required_filter_parameters):
        try:
            if call_function_with_arguments(filter_fn, **kwargs):
                if 'secret' in kwargs:
                    debug_msg = f'Skipping "{kwargs["secret"]}" due to `{filter_fn.path}`.'
                elif list(kwargs.keys()) == ['filename']:
                    # We want to make sure this is only run if we're skipping files (as compared
                    # to other filters that may include `filename` as a parameter).
                    debug_msg = f'Skipping "{kwargs["filename"]}" due to `{filter_fn.path}`'
                else:
                    debug_msg = f'Skipping secret due to `{filter_fn.path}`.'

                log.info(debug_msg)
                return True
        except TypeError:
            # Skipping non-compatible filters
            pass

    return False


def get_filters_with_parameter(*parameters: str) -> List[SelfAwareCallable]:
    """
    The issue of our method of dependency injection is that functions will be called multiple
    times. For example, if we have two functions:

    >>> def foo(filename: str): ...
    >>> def bar(filename: str, secret: str): ...

    our invocation of `call_function_with_arguments(filename=filename, secret=secret)`
    will run both of these functions. While expected, this results in multiple invocations of
    the same function, which can be less than ideal (especially if we have a heavy duty filter).

    To address this, we filter our filters with this function. It will return the functions
    that accept a minimum set of parameters, to avoid duplicative work. For instance,

    >>> get_filters_with_parameter('secret')
    [bar]
    """
    minimum_parameters = set(parameters)

    return [
        filter
        for filter in get_filters()
        if minimum_parameters <= filter.injectable_variables
    ]
