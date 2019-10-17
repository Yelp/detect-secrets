from __future__ import absolute_import

try:
    from backports import configparser
except ImportError:  # pragma: no cover
    import configparser
import base64
import math
import re
import string
from abc import ABCMeta
from abc import abstractmethod
from contextlib import contextmanager

import yaml

from .base import BasePlugin
from .base import classproperty
from .common.filetype import determine_file_type
from .common.filetype import FileType
from .common.filters import is_false_positive
from .common.ini_file_parser import IniFileParser
from .common.yaml_file_parser import YamlFileParser
from detect_secrets.core.potential_secret import PotentialSecret


class HighEntropyStringsPlugin(BasePlugin):
    """Base class for string pattern matching"""

    __metaclass__ = ABCMeta

    def __init__(self, charset, limit, exclude_lines_regex, automaton, *args):
        if limit < 0 or limit > 8:
            raise ValueError(
                'The limit set for HighEntropyStrings must be between 0.0 and 8.0',
            )

        self.charset = charset
        self.entropy_limit = limit
        self.automaton = automaton
        self.regex = re.compile(r'([\'"])([%s]+)(\1)' % charset)

        super(HighEntropyStringsPlugin, self).__init__(
            exclude_lines_regex=exclude_lines_regex,
        )

    def analyze(self, file, filename, debug_output_raw=False, output_verified_false=False):
        file_type_analyzers = (
            (self._analyze_ini_file(), configparser.Error),
            (self._analyze_yaml_file, yaml.YAMLError),
            (super(HighEntropyStringsPlugin, self).analyze, Exception),
            (self._analyze_ini_file(add_header=True), configparser.Error),
        )

        for analyze_function, exception_class in file_type_analyzers:
            try:
                output = analyze_function(file, filename)
                if output:
                    return output
            except exception_class:
                pass

            file.seek(0)

        return {}

    def calculate_shannon_entropy(self, data):
        """Returns the entropy of a given string.

        Borrowed from: http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html.

        :param data:  string. The word to analyze.
        :returns:       float, between 0.0 and 8.0
        """
        if not data:  # pragma: no cover
            return 0

        entropy = 0
        for x in self.charset:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        return entropy

    def analyze_string_content(self, string, line_num, filename, debug_output_raw=False):
        """Searches string for custom pattern, and captures all high entropy strings that
        match self.regex, with a limit defined as self.entropy_limit.
        """
        output = {}

        for result in self.secret_generator(string):
            if is_false_positive(result, self.automaton):
                continue

            secret = PotentialSecret(self.secret_type, filename, result, line_num)
            secret = PotentialSecret(
                self.secret_type,
                filename,
                result,
                line_num,
                debug_output_raw=debug_output_raw,
            )
            output[secret] = secret

        return output

    def secret_generator(self, string, *args, **kwargs):
        # There may be multiple strings on the same line
        results = self.regex.findall(string)
        for result in results:
            # To accommodate changing self.regex, due to different filetypes
            if isinstance(result, tuple):
                result = result[1]

            entropy_value = self.calculate_shannon_entropy(result)
            if entropy_value > self.entropy_limit:
                yield result

    def adhoc_scan(self, string):
        # Since it's an individual string, it's just bad UX to require quotes
        # around the expected secret.
        with self.non_quoted_string_regex():
            results = self.analyze_string(
                string,
                line_num=0,
                filename='does_not_matter',
            )

            # NOTE: Trailing space allows for nicer formatting
            output = 'False' if not results else 'True '
            if self.regex.search(string):
                output += ' ({})'.format(
                    round(self.calculate_shannon_entropy(string), 3),
                )

            return output

    @contextmanager
    def non_quoted_string_regex(self):
        """For certain file formats, strings need not necessarily follow the
        normal convention of being denoted by single or double quotes. In these
        cases, we modify the regex accordingly.

        Public, because detect_secrets.core.audit needs to reference it.
        """
        old_regex = self.regex

        regex_alternative = r'^([{}]+)$'.format(re.escape(self.charset))
        self.regex = re.compile(regex_alternative)

        try:
            yield
        finally:
            self.regex = old_regex

    def _analyze_ini_file(self, add_header=False):
        """
        :returns: same format as super().analyze()
        """
        def wrapped(file, filename):
            potential_secrets = {}

            with self.non_quoted_string_regex():
                for value, lineno in IniFileParser(
                    file,
                    add_header,
                    exclude_lines_regex=self.exclude_lines_regex,
                ).iterator():
                    potential_secrets.update(
                        self.analyze_string(
                            value,
                            lineno,
                            filename,
                        ),
                    )

            return potential_secrets

        return wrapped

    def _analyze_yaml_file(self, file, filename):
        """
        :returns: same format as super().analyze()
        """
        if determine_file_type(filename) != FileType.YAML:
            # The yaml parser is pretty powerful. It eagerly
            # parses things when it's not even a yaml file. Therefore,
            # we use this heuristic to quit early if appropriate.
            raise yaml.YAMLError

        parser = YamlFileParser(
            file,
            exclude_lines_regex=self.exclude_lines_regex,
        )
        data = parser.json()
        # If the file is all comments
        if not data:
            raise yaml.YAMLError

        ignored_lines = parser.get_ignored_lines()
        potential_secrets = {}

        to_search = [data]
        with self.non_quoted_string_regex():
            while len(to_search) > 0:
                item = to_search.pop()

                if '__line__' not in item:
                    for key in item:
                        obj = item[key] if isinstance(item, dict) else key
                        if isinstance(obj, dict):
                            to_search.append(obj)
                    continue

                if item['__line__'] in ignored_lines:
                    continue

                # An isinstance check doesn't work in py2
                # so we need the __is_binary__ field.
                string_to_scan = (
                    self.decode_binary(item['__value__'])
                    if item['__is_binary__']
                    else item['__value__']
                )

                secrets = self.analyze_string(
                    string_to_scan,
                    item['__line__'],
                    filename,
                )

                if item['__is_binary__']:
                    secrets = self._encode_yaml_binary_secrets(secrets)

                potential_secrets.update(secrets)

        return potential_secrets

    def _encode_yaml_binary_secrets(self, secrets):
        new_secrets = {}
        """The secrets dict format is
        `{PotentialSecret: PotentialSecret}`, where both key and
        value are the same object. Therefore, we can just mutate
        the potential secret once.
        """
        for potential_secret in secrets.keys():
            secret_in_yaml_format = yaml.dump(
                self.encode_to_binary(potential_secret.secret_value),
            ).replace(
                '!!binary ',
                '',
            )

            potential_secret.set_secret(secret_in_yaml_format)

            new_secrets[potential_secret] = potential_secret

        return new_secrets

    @abstractmethod
    def decode_binary(self, bytes_object):  # pragma: no cover
        """Converts the bytes to a string which can be checked for
        high entropy."""
        pass

    @abstractmethod
    def encode_to_binary(self, string):  # pragma: no cover
        """Converts a string (usually a high-entropy secret) to
        binary. Usually the inverse of decode_binary."""
        pass


class HexHighEntropyString(HighEntropyStringsPlugin):
    """Scans for random-looking hex encoded strings."""

    secret_type = 'Hex High Entropy String'

    def __init__(self, hex_limit, exclude_lines_regex=None, automaton=None, **kwargs):
        super(HexHighEntropyString, self).__init__(
            charset=string.hexdigits,
            limit=hex_limit,
            exclude_lines_regex=exclude_lines_regex,
            automaton=automaton,
        )

    @classproperty
    def disable_flag_text(cls):
        return 'no-hex-string-scan'

    @classproperty
    def default_options(cls):
        return {
            'hex_limit': 3,
        }

    @property
    def __dict__(self):
        output = super(HighEntropyStringsPlugin, self).__dict__
        output.update({
            'hex_limit': self.entropy_limit,
        })

        return output

    def calculate_shannon_entropy(self, data):
        """
        In our investigations, we have found that when the input is all digits,
        the number of false positives we get greatly exceeds realistic true
        positive scenarios.

        Therefore, this tries to capture this heuristic mathemetically.

        We do this by noting that the maximum shannon entropy for this charset
        is ~3.32 (e.g. "0123456789", with every digit different), and we want
        to lower that below the standard limit, 3. However, at the same time,
        we also want to accommodate the fact that longer strings have a higher
        chance of being a true positive, which means "01234567890123456789"
        should be closer to the maximum entropy than the shorter version.
        """
        entropy = super(HexHighEntropyString, self).calculate_shannon_entropy(data)
        if len(data) == 1:
            return entropy

        try:
            int(data)

            # This multiplier was determined through trial and error, with the
            # intent of keeping it simple, yet achieving our goals.
            entropy -= 1.2 / math.log(len(data), 2)
        except ValueError:
            pass

        return entropy

    def decode_binary(self, bytes_object):
        return bytes_object.decode('utf-8')

    def encode_to_binary(self, string):
        return string.encode('utf-8')


class Base64HighEntropyString(HighEntropyStringsPlugin):
    """Scans for random-looking base64 encoded strings."""

    secret_type = 'Base64 High Entropy String'

    def __init__(self, base64_limit, exclude_lines_regex=None, automaton=None, **kwargs):
        super(Base64HighEntropyString, self).__init__(
            charset=string.ascii_letters + string.digits + '+/=',
            limit=base64_limit,
            exclude_lines_regex=exclude_lines_regex,
            automaton=automaton,
        )

    @classproperty
    def disable_flag_text(cls):
        return 'no-base64-string-scan'

    @classproperty
    def default_options(cls):
        return {
            'base64_limit': 4.5,
        }

    @property
    def __dict__(self):
        output = super(HighEntropyStringsPlugin, self).__dict__
        output.update({
            'base64_limit': self.entropy_limit,
        })

        return output

    def decode_binary(self, bytes_object):
        return base64.b64encode(bytes_object).decode('utf-8')

    def encode_to_binary(self, string):
        return base64.b64decode(string)
