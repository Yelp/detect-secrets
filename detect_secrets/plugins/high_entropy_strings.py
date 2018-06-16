from __future__ import absolute_import

import configparser
import math
import os
import re
import string
from contextlib import contextmanager

import yaml

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret


YAML_EXTENSIONS = (
    '.yaml',
    '.yml',
)


class HighEntropyStringsPlugin(BasePlugin):
    """Base class for string pattern matching"""

    secret_type = 'High Entropy String'

    def __init__(self, charset, limit, *args):
        if limit < 0 or limit > 8:
            raise ValueError(
                'The limit set for HighEntropyStrings must be between 0.0 and 8.0'
            )

        self.charset = charset
        self.entropy_limit = limit
        self.regex = re.compile(r'([\'"])([%s]+)(\1)' % charset)

        # Allow whitelisting individual lines.
        # TODO: Update for not just python comments?
        self.ignore_regex = re.compile(r'# ?pragma: ?whitelist[ -]secret')

    def analyze(self, file, filename):
        file_type_analyzers = (
            ('_analyze_ini_file', configparser.Error,),
            ('_analyze_yaml_file', yaml.YAMLError,),
        )

        for function, error in file_type_analyzers:
            try:
                return getattr(self, function)(file, filename)
            except error:
                file.seek(0)

        return super(HighEntropyStringsPlugin, self).analyze(file, filename)

    def calculate_shannon_entropy(self, data):
        """Returns the entropy of a given string.

        Borrowed from: http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html.

        :param string:  string. The word to analyze.
        :param charset: string. The character set from which to calculate entropy.
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

    def analyze_string(self, string, line_num, filename):
        """Searches string for custom pattern, and captures all high entropy strings that
        match self.regex, with a limit defined as self.entropy_limit.
        """

        output = {}

        if self.ignore_regex.search(string):
            return output

        # There may be multiple strings on the same line
        results = self.regex.findall(string)
        for result in results:
            # To accommodate changing self.regex, due to different filetypes
            if isinstance(result, tuple):
                result = result[1]

            entropy_value = self.calculate_shannon_entropy(result)
            if entropy_value > self.entropy_limit:
                secret = PotentialSecret(self.secret_type, filename, line_num, result)
                output[secret] = secret

        return output

    def _analyze_ini_file(self, file, filename):
        """
        :returns: same format as super().analyze()
        """
        potential_secrets = {}

        with self._non_quoted_string_regex():
            for value, lineno in IniFileParser(file).iterator():
                potential_secrets.update(self.analyze_string(
                    value,
                    lineno,
                    filename,
                ))

        return potential_secrets

    def _analyze_yaml_file(self, file, filename):
        """
        :returns: same format as super().analyze()
        """
        if os.path.splitext(filename)[1] not in YAML_EXTENSIONS:
            # The yaml parser is pretty powerful. It eagerly
            # parses things when it's not even a yaml file. Therefore,
            # we use this heuristic to quit early if appropriate.
            raise yaml.YAMLError

        data = YamlLineInjector(file).json()
        potential_secrets = {}

        to_search = [data]
        with self._non_quoted_string_regex():
            while len(to_search) > 0:
                item = to_search.pop()

                try:
                    if '__line__' in item:
                        potential_secrets.update(
                            self.analyze_string(
                                item['__value__'],
                                item['__line__'],
                                filename,
                            ),
                        )
                        continue

                    for key in item:
                        obj = item[key] if isinstance(item, dict) else key
                        if isinstance(obj, dict):
                            to_search.append(obj)
                except TypeError:
                    pass

        return potential_secrets

    @property
    def __dict__(self):
        output = super(HighEntropyStringsPlugin, self).__dict__
        output.update({
            'limit': self.entropy_limit,
        })

        return output

    @contextmanager
    def _non_quoted_string_regex(self):
        """For certain file formats, strings need not necessarily follow the
        normal convention of being denoted by single or double quotes. In these
        cases, we modify the regex accordingly.
        """
        old_regex = self.regex
        self.regex = re.compile(r'^([%s]+)$' % self.charset)

        try:
            yield
        finally:
            self.regex = old_regex


class HexHighEntropyString(HighEntropyStringsPlugin):
    """HighEntropyStringsPlugin for hex strings"""

    def __init__(self, limit, *args):
        super(HexHighEntropyString, self).__init__(string.hexdigits, limit)


class Base64HighEntropyString(HighEntropyStringsPlugin):
    """HighEntropyStringsPlugin for base64 encoded strings"""

    def __init__(self, limit, *args):
        super(Base64HighEntropyString, self).__init__(
            string.ascii_letters + string.digits + '+/=',
            limit
        )


class IniFileParser(object):

    def __init__(self, file):
        self.parser = configparser.ConfigParser()
        self.parser.optionxform = str
        self.parser.read_file(file)

        # Hacky way to keep track of line location
        file.seek(0)
        self.lines = list(map(lambda x: x.strip(), file.readlines()))
        self.line_offset = 0

    def iterator(self):
        if not self.parser.sections():
            # To prevent cases where it's not an ini file, but the parser
            # helpfully attempts to parse everything to a DEFAULT section,
            # when not explicitly provided.
            raise configparser.Error

        for section_name, _ in self.parser.items():
            for key, values in self.parser.items(section_name):
                for value, offset in self._get_value_and_line_offset(
                        key,
                        values,
                ):
                    yield value, offset

    def _get_value_and_line_offset(self, key, values):
        """Returns the index of the location of key, value pair in lines.

        :type key: str
        :param key: key, in config file.

        :type values: str
        :param values: values for key, in config file. This is plural,
            because you can have multiple values per key. Eg.

            >>> key =
            ...     value1
            ...     value2

        :type lines: list
        :param lines: a collection of lines-so-far in file

        :rtype: list(tuple)
        """
        values_list = self._construct_values_list(values)
        current_value_list_index = 0
        output = []
        lines_modified = False

        first_line_regex = re.compile(r'^\s*{}[ :=]+{}'.format(
            key,
            values_list[current_value_list_index],
        ))
        comment_regex = re.compile(r'\s*[;#]')
        for index, line in enumerate(self.lines):
            if current_value_list_index == 0:
                if first_line_regex.match(line):
                    output.append((
                        values_list[current_value_list_index],
                        self.line_offset + index + 1,
                    ))

                    current_value_list_index += 1

                continue

            # Check ignored lines before checking values, because
            # you can write comments *after* the value.

            # Ignore blank lines
            if not line.strip():
                continue

            # Ignore comments
            if comment_regex.match(line):
                continue

            if current_value_list_index == len(values_list):
                if index == 0:
                    index = 1       # don't want to count the same line again

                self.line_offset += index
                self.lines = self.lines[index:]
                lines_modified = True

                break
            else:
                output.append((
                    values_list[current_value_list_index],
                    self.line_offset + index + 1,
                ))

                current_value_list_index += 1

        if not lines_modified:
            # No more lines left, if loop was not explicitly left.
            self.lines = []

        return output

    @staticmethod
    def _construct_values_list(values):
        """
        This values_list is a strange construction, because of ini format.
        We need to extract the values with the following supported format:

            >>> key = value0
            ...     value1
            ...
            ...     # comment line here
            ...     value2

        given that normally, either value0 is supplied, or (value1, value2),
        but still allowing for all three at once.

        Furthermore, with the configparser, we will get a list of values,
        and intermediate blank lines, but no comments. This means that we can't
        merely use the count of values' items to heuristically "skip ahead" lines,
        because we still have to manually parse through this.

        Therefore, we construct the values_list in the following fashion:
            1. Keep the first value (in the example, this is `value0`)
            2. For all other values, ignore blank lines.
        Then, we can parse through, and look for values only.
        """
        values_list = values.splitlines()
        return values_list[:1] + list(
            filter(
                lambda x: x,
                values_list[1:],
            )
        )


class YamlLineInjector(object):
    """
    Yaml config files are interesting, because they don't necessarily conform
    to our basic regex for detecting HighEntropyStrings as strings don't
    need to be quoted.

    This causes interesting issues, because our regex won't catch non-quoted
    strings, and if we ignore the quoting requirement, then we increase our
    false positive rate, because any long string would have high entropy.

    Therefore, we take a different approach: intercept the parsing of the yaml
    file to identify string values. This assumes:

        1. Secrets are strings
        2. Secrets are not keys

    Then, we calculate the entropy of those string values.

    The difficulty comes from determining the line number which these values
    come from. To do this, we transform the string into a dictionary of
    meta-tags, in the following format:

    >>> {
        'key': {
            '__value__': value,
            '__line__': <line_number>,
        }
    }

    This way, we can quickly identify the line number for auditing at a later
    stage.

    This parsing method is inspired by https://stackoverflow.com/a/13319530.
    """

    def __init__(self, file):
        self.loader = yaml.SafeLoader(file.read())

        self.loader.compose_node = self._compose_node_shim

    def json(self):
        return self.loader.get_single_data()

    def _compose_node_shim(self, parent, index):
        line = self.loader.line

        node = yaml.composer.Composer.compose_node(self.loader, parent, index)
        node.__line__ = line + 1

        if node.tag.endswith(':map'):
            return self._tag_dict_values(node)

        # TODO: Not sure if need to do :seq

        return node

    def _tag_dict_values(self, map_node):
        """
        :type map_node: yaml.nodes.MappingNode
        :param map_node: It looks like map_node.value contains a list of
            pair tuples, corresponding to key,value pairs.
        """
        new_values = []
        for key, value in map_node.value:
            if not value.tag.endswith(':str'):
                new_values.append((key, value,))
                continue

            augmented_string = yaml.nodes.MappingNode(
                tag=map_node.tag,
                value=[
                    self._create_key_value_pair_for_mapping_node_value(
                        '__value__',
                        value.value,
                        'tag:yaml.org,2002:str',
                    ),
                    self._create_key_value_pair_for_mapping_node_value(
                        '__line__',
                        str(value.__line__),
                        'tag:yaml.org,2002:int',
                    ),
                ],
            )

            new_values.append((key, augmented_string,))

        output = yaml.nodes.MappingNode(
            tag=map_node.tag,
            value=new_values,
            start_mark=map_node.start_mark,
            end_mark=map_node.end_mark,
            flow_style=map_node.flow_style,
        )
        return output

    def _create_key_value_pair_for_mapping_node_value(self, key, value, tag):
        return (
            yaml.nodes.ScalarNode(
                tag='tag:yaml.org,2002:str',
                value=key,
            ),
            yaml.nodes.ScalarNode(
                tag=tag,
                value=value,
            ),
        )
