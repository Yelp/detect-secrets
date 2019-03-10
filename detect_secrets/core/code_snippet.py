import codecs
import itertools

from .color import AnsiColor
from .color import colorize


class CodeSnippetHighlighter:

    def get_code_snippet(self, filename, line_number, lines_of_context=5):
        """
        :type filename: str

        :type line_number: int
        :param line_number: line which you want to focus on

        :type lines_of_context: int
        :param lines_of_context: how many lines to display around the line you want
            to focus on.

        :rtype: CodeSnippet
        """
        secret_line_index = line_number - 1
        end_line = secret_line_index + lines_of_context + 1

        if secret_line_index <= lines_of_context:
            start_line = 0
            index_of_secret_in_output = secret_line_index
        else:
            start_line = secret_line_index - lines_of_context
            index_of_secret_in_output = lines_of_context

        return CodeSnippet(
            list(
                itertools.islice(
                    self._get_lines_in_file(filename),
                    start_line,
                    end_line,
                ),
            ),
            start_line,
            index_of_secret_in_output,
        )

    def _get_lines_in_file(self, filename):
        """
        :rtype: list
        """
        with codecs.open(filename, encoding='utf-8') as file:
            return file.read().splitlines()


class CodeSnippet:

    def __init__(self, snippet, start_line, target_index):
        """
        :type snippet: list
        :param snippet: lines of code extracted from file

        :type start_line: int
        :param start_line: first line number in segment

        :type target_index: int
        :param target_index: index in snippet of target line
        """
        self.lines = snippet
        self.start_line = start_line
        self.target_index = target_index

    @property
    def target_line(self):
        return self.lines[self.target_index]

    @target_line.setter
    def target_line(self, value):
        self.lines[self.target_index] = value

    def add_line_numbers(self):
        for index, line in enumerate(self.lines):
            self.lines[index] = u'{}:{}'.format(
                self.get_line_number(self.start_line + index + 1),
                line,
            )

        return self

    def highlight_line(self, payload):
        """
        :type payload: str
        :param payload: string to highlight, on chosen line
        """
        index_of_payload = self.target_line.lower().index(payload.lower())
        end_of_payload = index_of_payload + len(payload)

        self.target_line = u'{}{}{}'.format(
            self.target_line[:index_of_payload],
            self.apply_highlight(self.target_line[index_of_payload:end_of_payload]),
            self.target_line[end_of_payload:],
        )

        return self

    def get_line_number(self, line_number):
        """Broken out, for custom colorization."""
        return colorize(
            str(line_number),
            AnsiColor.LIGHT_GREEN,
        )

    def apply_highlight(self, payload):
        """Broken out, for custom colorization."""
        return colorize(
            payload,
            AnsiColor.RED_BACKGROUND,
        )

    def __str__(self):
        return '\n'.join(self.lines)
