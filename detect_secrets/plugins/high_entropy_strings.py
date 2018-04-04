from __future__ import absolute_import

import math
import re
import string
from contextlib import contextmanager

from future import standard_library

from .base import BasePlugin
from detect_secrets.core.potential_secret import PotentialSecret
standard_library.install_aliases()
import configparser     # noqa: E402


INI_FILE_EXTENSIONS = (
    'ini',
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
        # Heuristically determine whether file is an ini-formatted file.
        for ext in INI_FILE_EXTENSIONS:
            if filename.endswith('.{}'.format(ext)):
                return self._analyze_ini_file(file, filename)

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
                    offset = self._get_line_offset(key, value, lines) + 1
                    line_offset += offset
                    lines = lines[offset:]

                    secrets = self.analyze_string(
                        value,
                        line_offset,
                        filename,
                    )

                    potential_secrets.update(secrets)

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
    def _get_line_offset(key, value, lines):
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
