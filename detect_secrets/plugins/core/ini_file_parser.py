import configparser
import re


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

        first_line_regex = re.compile(r'^\s*{}[ :=]+{}'.format(
            re.escape(key),
            re.escape(values_list[current_value_list_index]),
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
            ),
        )
