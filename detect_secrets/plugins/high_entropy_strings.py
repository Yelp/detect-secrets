from __future__ import absolute_import

import math
import os
import re
import string
from contextlib import contextmanager

import yaml
from future import standard_library

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret
standard_library.install_aliases()
import configparser     # noqa: E402


YAML_EXTENSIONS = (
    '.yaml',
    '.yml',
)


class HighEntropyStringsPlugin(BasePlugin):
    """Base class for string pattern matching"""

    secret_type = 'High Entropy String'

    def __init__(self, charset, limit, *args):
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
        match self.regex, with a limit defined as self.entropy_limit."""

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
        parser = configparser.ConfigParser()
        parser.read_file(file)

        potential_secrets = {}

        # Hacky way to keep track of line location.
        file.seek(0)
        lines = list(map(lambda x: x.strip(), file.readlines()))
        line_offset = 0

        with self._non_quoted_string_regex():
            for section_name, _ in parser.items():
                for key, value in parser.items(section_name):
                    # +1, because we don't want to double count lines
                    offset = self._get_line_offset_for_ini_files(
                        key,
                        value,
                        lines
                    ) + 1
                    line_offset += offset
                    lines = lines[offset:]

                    secrets = self.analyze_string(
                        value,
                        line_offset,
                        filename,
                    )

                    potential_secrets.update(secrets)

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

        yield

        self.regex = old_regex

    @staticmethod
    def _get_line_offset_for_ini_files(key, value, lines):
        """Returns the index of the location of key, value pair in lines.

        :type key: str
        :param key: key, in config file.

        :type value: str
        :param value: value for key, in config file.

        :type lines: list
        :param lines: a collection of lines-so-far in file
        """
        regex = re.compile(r'^{}[ :=]+{}'.format(key, value))
        for index, line in enumerate(lines):
            if regex.match(line):
                return index


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
