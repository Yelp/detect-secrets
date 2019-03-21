from __future__ import unicode_literals

try:
    from backports import configparser
except ImportError:  # pragma: no cover
    import configparser
import re


class EfficientParsingError(configparser.ParsingError):

    def append(self, lineno, line):
        """
        Rather than inefficiently add all the lines in the file
        to the error message like the CPython code from 1998.
        We just `return` because we will catch and `pass`
        the exception in `high_entropy_strings.py` anyway.
        """
        return


configparser.ParsingError = EfficientParsingError


class IniFileParser(object):

    _comment_regex = re.compile(r'\s*[;#]')

    def __init__(self, file, add_header=False, exclude_lines_regex=None):
        """
        :type file: file object

        :type add_header: bool
        :param add_header: whether or not to add a top-level [global] header.

        :type exclude_lines_regex: regex object
        :param exclude_lines_regex: optional regex for ignored lines.
        """
        self.parser = configparser.ConfigParser()
        try:
            # python2.7 compatible
            self.parser.optionxform = unicode
        except NameError:  # pragma: no cover
            # python3 compatible
            self.parser.optionxform = str

        self.exclude_lines_regex = exclude_lines_regex

        content = file.read()
        if add_header:
            # This supports environment variables, or other files that look
            # like config files, without a section header.
            content = '[global]\n' + content

        try:
            # python2.7 compatible
            self.parser.read_string(unicode(content))
        except NameError:  # pragma: no cover
            # python3 compatible
            self.parser.read_string(content)

        # Hacky way to keep track of line location
        file.seek(0)
        self.lines = [line.strip() for line in file.readlines()]
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
            because you can have multiple values per key. e.g.

            >>> key =
            ...     value1
            ...     value2

        :type lines: list
        :param lines: a collection of lines-so-far in file

        :rtype: list(tuple)
        """
        values_list = self._construct_values_list(values)
        if not values_list:
            return []

        current_value_list_index = 0
        output = []
        lines_modified = False

        for index, line in enumerate(self.lines):
            # Check ignored lines before checking values, because
            # you can write comments *after* the value.
            if not line.strip() or self._comment_regex.match(line):
                continue

            if (
                self.exclude_lines_regex and
                self.exclude_lines_regex.search(line)
            ):
                continue

            if current_value_list_index == 0:
                first_line_regex = re.compile(r'^\s*{}[ :=]+{}'.format(
                    re.escape(key),
                    re.escape(values_list[current_value_list_index]),
                ))
                if first_line_regex.match(line):
                    output.append((
                        values_list[current_value_list_index],
                        self.line_offset + index + 1,
                    ))
                    current_value_list_index += 1
                continue

            if current_value_list_index == len(values_list):
                if index == 0:
                    index = 1  # don't want to count the same line again
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
        lines = values.splitlines()
        values_list = lines[:1]
        values_list.extend(filter(None, lines[1:]))
        return values_list
