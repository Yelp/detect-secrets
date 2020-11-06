from collections import defaultdict
from functools import lru_cache
from importlib import import_module
from typing import Any
from typing import Callable
from typing import Dict
from typing import Generator
from typing import IO
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from . import plugins
from ..settings import get_settings
from ..types import SelfAwareCallable
from .log import log
from .plugins.util import Plugin
from .potential_secret import PotentialSecret


class PatchedFile:
    """This exists so that we can do typecasting, without importing unidiff."""
    path: str

    def __iter__(self) -> Generator:
        pass


class SecretsCollection:
    def __init__(self) -> None:
        self.data: Dict[str, Set[PotentialSecret]] = defaultdict(set)

    @classmethod
    def load_from_baseline(cls, baseline: Dict[str, Any]) -> 'SecretsCollection':
        output = cls()
        for filename in baseline['results']:
            for item in baseline['results'][filename]:
                secret = PotentialSecret.load_secret_from_dict(item)
                output[filename].add(secret)

        return output

    @property
    def files(self) -> Set[str]:
        return set(self.data.keys())

    def scan_file(self, filename: str) -> None:
        if not get_plugins():       # pragma: no cover
            log.warning('No plugins to scan with!')
            return

        # First, we filter on filename, so that we can skip whole files if we've filtered
        # them out.
        for filter_fn in get_filters():
            if _inject_variables(filter_fn, filename=filename):
                log.info(f'Skipping "{filename}" due to "{filter_fn.path}"')
                return

        try:
            with open(filename) as f:
                for secret in _iterate_through_secrets_in_file(f):
                    self[filename].add(secret)
        except IOError:
            log.warning(f'Unable to open file: {filename}')

    def scan_diff(self, diff: str) -> None:
        """
        :raises: UnidiffParseError
        """
        if not get_plugins():       # pragma: no cover
            log.warning('No plugins to scan with!')
            return

        # Local imports, so that we don't need to require unidiff for versions of
        # detect-secrets that don't use it.
        try:
            from unidiff import PatchSet
        except ImportError:     # pragma: no cover
            raise NotImplementedError(
                'SecretsCollection.scan_diff requires `unidiff` to work. Try pip '
                'installing that package, and try again.',
            )

        filters = get_filters()
        patch_set = PatchSet.from_string(diff)
        for patch_file in patch_set:
            filename = patch_file.path

            for filter_fn in filters:
                if _inject_variables(filter_fn, filename=filename):
                    log.info(f'Skipping "{filename}" due to "{filter_fn.path}"')
                    break
            else:
                for secret in _iterate_through_secrets_in_patch_file(patch_file):
                    self[filename].add(secret)

    def trim(
        self,
        scanned_results: 'SecretsCollection',
        filelist: Optional[List[str]] = None,
    ) -> None:
        """
        Removes invalid entries in the current SecretsCollection.

        This behaves *kinda* like set intersection and left-join. That is, for matching files,
        a set intersection is performed. For non-matching files, only the files in `self` will
        be kept.

        This is because we may not be constructing the other SecretsCollection with the same
        information as we are with the current SecretsCollection, and we cannot infer based on
        incomplete information. As such, we will keep the status quo.

        Assumptions:
            1. Both `scanned_results` and the current SecretsCollection are constructed using
               the same settings (otherwise, we can't determine whether a missing secret is due
               to newly filtered secrets, or actually removed).

        :param filelist: files without secrets are not present in `scanned_results`. Therefore,
            by supplying this additional filelist, we can assert that if an entry is missing in
            `scanned_results`, it must not have secrets in it.
        """
        if not filelist:
            fileset = set([])
        else:
            fileset = set(filelist)

        # Unfortunately, we can't merely do a set intersection since we want to update the line
        # numbers (if applicable). Therefore, this does it manually.
        result: Dict[str, Set[PotentialSecret]] = defaultdict(set)
        for filename, secret in scanned_results:
            if filename not in self.files:
                continue

            # This will use the latest information from the scanned results.
            if secret in self[filename]:
                result[filename].add(secret)

        for filename in self.files:
            # If this is already populated by scanned_results, then the set intersection
            # is already completed.
            if filename in result:
                continue

            # All secrets relating to that file was removed.
            # We know this because:
            #   1. It's a file that was scanned (in filelist)
            #   2. It would have been in the baseline, if there were secrets...
            #   3. ...but it isn't.
            if filename in fileset:
                continue

            result[filename] = self[filename]

        self.data = result

    def json(self) -> Dict[str, Any]:
        """Custom JSON encoder"""
        output = {}
        for filename, secrets in self.data.items():
            output[filename] = sorted(
                [secret.json() for secret in secrets],
                # TODO: Handle cases when line numbers are not supplied
                key=lambda x: x['line_number'],
            )

        return output

    def exactly_equals(self, other: Any) -> bool:
        return self.__eq__(other, strict=True)      # type: ignore

    def __getitem__(self, filename: str) -> Set[PotentialSecret]:
        return self.data[filename]

    def __setitem__(self, filename: str, value: Set[PotentialSecret]) -> None:
        self.data[filename] = value

    def __iter__(self) -> Generator[Tuple[str, PotentialSecret], None, None]:
        for filename, secrets in self.data.items():
            for secret in secrets:
                yield filename, secret

    def __bool__(self) -> bool:
        return bool(self.data)

    def __eq__(self, other: Any, strict: bool = False) -> bool:
        """
        :param strict: if strict, will return False even if secrets match
            (e.g. if line numbers are different)
        """
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        if self.files != other.files:
            return False

        for filename in self.files:
            self_mapping = {secret.secret_hash: secret for secret in self[filename]}
            other_mapping = {secret.secret_hash: secret for secret in other[filename]}

            # Since PotentialSecret is hashable, we compare their identities through this.
            if set(self_mapping.values()) != set(other_mapping.values()):
                return False

            if not strict:
                continue

            for secretA in self_mapping.values():
                secretB = other_mapping[secretA.secret_hash]

                valuesA = vars(secretA)
                valuesA.pop('secret_value')
                valuesB = vars(secretB)
                valuesB.pop('secret_value')

                if valuesA != valuesB:
                    return False

        return True

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __sub__(self, other: Any) -> 'SecretsCollection':
        """This behaves like set subtraction."""
        if not isinstance(other, SecretsCollection):
            raise NotImplementedError

        # We want to create a copy to follow convention and adhere to the principle
        # of least surprise.
        output = SecretsCollection()
        for filename in other.files:
            if filename not in self.files:
                continue

            output[filename] = self[filename] - other[filename]

        return output


@lru_cache(maxsize=1)
def get_plugins() -> List[Plugin]:
    return [
        plugins.initialize.from_plugin_classname(classname)
        for classname in get_settings().plugins
    ]


@lru_cache(maxsize=1)
def get_filters() -> List[SelfAwareCallable]:
    output = []
    for path, config in get_settings().filters.items():
        module_path, function_name = path.rsplit('.', 1)
        try:
            function = getattr(import_module(module_path), function_name)
        except (ModuleNotFoundError, AttributeError):
            log.warn(f'Invalid filter: {path}')
            continue

        # We attach this metadata to the function itself, so that we don't need to
        # compute it everytime. This will allow for dependency injection for filters.
        function.injectable_variables = set(_get_injectable_variables(function))
        output.append(function)

        # This is for better logging.
        function.path = path

    return output


def _get_injectable_variables(func: Callable) -> Tuple[str, ...]:
    """
    The easiest way to understand this is to see it as an example:
        >>> def func(a, b=1, *args, c, d=2, **kwargs):
        ...     e = 5
        >>>
        >>> print(func.__code__.co_varnames)
        ('a', 'b', 'c', 'd', 'args', 'kwargs', 'e')
        >>> print(func.__code__.co_argcount)    # `a` and `b`
        2
        >>> print(func.__code__.co_kwonlyargcount)  # `c` and `d`
        2
    """
    variable_names = func.__code__.co_varnames
    arg_count = func.__code__.co_argcount + func.__code__.co_kwonlyargcount

    return variable_names[:arg_count]


def _inject_variables(func: SelfAwareCallable, **kwargs: Any) -> Any:
    variables_to_inject = set(kwargs.keys())
    values = {
        key: kwargs[key]
        for key in (variables_to_inject & func.injectable_variables)
    }

    if set(values.keys()) != func.injectable_variables:
        return

    return func(**values)


def _iterate_through_secrets_in_file(file: IO) -> Generator[PotentialSecret, None, None]:
    log.info(f'Checking file: {file.name}')

    for secret in _process_line_based_plugins(file.readlines(), filename=file.name):
        yield secret

    file.seek(0)

    for secret in _process_file_based_plugins(file):
        yield secret


def _iterate_through_secrets_in_patch_file(
    patch_file: PatchedFile,
) -> Generator[PotentialSecret, None, None]:
    for secret in _process_line_based_plugins(
        [
            line.value
            for chunk in patch_file
            # target_lines refers to incoming (new) changes
            for line in chunk.target_lines()
            if line.is_added
        ],
        filename=patch_file.path,
    ):
        yield secret


def _process_line_based_plugins(
    lines: List[str],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    for index, line in enumerate(lines):
        line = line.rstrip()

        # Next, we apply line-specific filters, and see whether that allows us to quit early.
        if any([
            _inject_variables(filter_fn, filename=filename, line=line)
            for filter_fn in get_filters()
        ]):
            continue

        for plugin in get_plugins():
            secrets = plugin.analyze_line(line, line_num=index + 1, filename=filename)
            if not secrets:
                continue

            for secret in secrets:
                # Lastly, we apply (filename, line, secret) filters, and see if we should consider
                # the result an actual secret.
                if any([
                    _inject_variables(
                        filter_fn,
                        filename=filename,
                        line=line,
                        secret=secret.secret_value,
                    )
                    for filter_fn in get_filters()
                ]):
                    continue

                yield secret


def _process_file_based_plugins(file: IO) -> Generator[PotentialSecret, None, None]:
    # TODO
    return []
