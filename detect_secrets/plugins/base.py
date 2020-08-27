import re
from abc import ABCMeta
from abc import abstractmethod
from abc import abstractproperty

from detect_secrets.core.code_snippet import CodeSnippetHighlighter
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.common.constants import ALLOWLIST_REGEXES


# Note: In this whitepaper (Section V-D), it suggests that there's an
#       80% chance of finding a multi-factor secret (e.g. username +
#       password) within five lines of context, before and after a secret.
#
#       This number can be tweaked if desired, at the cost of performance.
#
#       https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
LINES_OF_CONTEXT = 5


class classproperty(property):
    def __get__(self, cls, owner):
        return classmethod(self.fget).__get__(None, owner)()


class BasePlugin:
    """
    This is an abstract class to define Plugins API.

    :type secret_type: str
    :param secret_type: uniquely identifies the type of secret found in the baseline.
        e.g. {
            "hashed_secret": <hash>,
            "line_number": 123,
            "type": <secret_type>,
        }

        Be warned of modifying the `secret_type` once rolled out to clients since
        the hashed_secret uses this value to calculate a unique hash (and the baselines
        will no longer match).

    :type disable_flag_text: str
    :param disable_flag_text: text used as an command line argument flag to disable
        this specific plugin scan. does not include the `--` prefix.

    :type default_options: Dict[str, Any]
    :param default_options: configurable options to modify plugin behavior
    """
    __metaclass__ = ABCMeta

    @abstractproperty
    def secret_type(self):
        raise NotImplementedError

    def __init__(
        self,
        exclude_lines_regex=None,
        should_verify=False,
        false_positive_heuristics=None,
        **kwargs
    ):
        """
        :type exclude_lines_regex: str|None
        :param exclude_lines_regex: optional regex for ignored lines.

        :type should_verify: bool

        :type false_positive_heuristics: List[Callable]|None
        :param false_positive_heuristics: List of fp-heuristic functions
        applicable to this plugin
        """
        self.exclude_lines_regex = (
            re.compile(exclude_lines_regex)
            if exclude_lines_regex
            else None
        )

        self.should_verify = should_verify

        self.false_positive_heuristics = false_positive_heuristics or []

    @classproperty
    def disable_flag_text(cls):
        name = cls.__name__
        if name.endswith('Detector'):
            name = name[:-len('Detector')]

        # Turn camel case into hyphenated strings
        name_hyphen = ''
        for letter in name:
            if letter.upper() == letter and name_hyphen:
                name_hyphen += '-'
            name_hyphen += letter.lower()

        return 'no-{}-scan'.format(name_hyphen)

    @classproperty
    def default_options(cls):
        return {}

    def _is_excluded_line(self, line):
        return (
            any(
                allowlist_regex.search(line)
                for allowlist_regex in ALLOWLIST_REGEXES
            )
            or
            (
                self.exclude_lines_regex and
                self.exclude_lines_regex.search(line)
            )
        )

    def analyze(self, file, filename):
        """
        :param file:     The File object itself.
        :param filename: string; filename of File object, used for creating
                         PotentialSecret objects
        :returns         dictionary representation of set (for random access by hash)
                         { detect_secrets.core.potential_secret.__hash__:
                               detect_secrets.core.potential_secret         }
        """
        potential_secrets = {}
        file_lines = tuple(file.readlines())
        for line_num, line in enumerate(file_lines, start=1):
            results = self.analyze_line(line, line_num, filename)
            if (
                not results
                or
                self._is_excluded_line(line)
            ):
                continue

            if not self.should_verify:
                potential_secrets.update(results)
                continue

            filtered_results = {}
            for result in results:
                snippet = CodeSnippetHighlighter().get_code_snippet(
                    file_lines,
                    result.lineno,
                    lines_of_context=LINES_OF_CONTEXT,
                )

                is_verified = self.verify(result.secret_value, context=str(snippet))
                if is_verified == VerifiedResult.VERIFIED_TRUE:
                    result.is_verified = True

                if is_verified != VerifiedResult.VERIFIED_FALSE:
                    filtered_results[result] = result

            potential_secrets.update(filtered_results)

        return potential_secrets

    def analyze_line(self, string, line_num, filename):
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        Note: line_num and filename are used for PotentialSecret creation only.
        """
        return self.analyze_string_content(
            string,
            line_num,
            filename,
        )

    @abstractmethod
    def analyze_string_content(self, string, line_num, filename):
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        Note: line_num and filename are used for PotentialSecret creation only.
        """
        raise NotImplementedError

    @abstractmethod
    def secret_generator(self, string, *args, **kwargs):
        """Flags secrets in a given string, and yields the raw secret value.
        Used in self.analyze_line for PotentialSecret creation.

        :type string: str
        :param string: the secret to scan

        :rtype: iter
        :returns: Of all the identifiers found
        """
        raise NotImplementedError

    def adhoc_scan(self, string):
        """To support faster discovery, we want the ability to conveniently
        check what different plugins say regarding a single line/secret. This
        supports that.

        This is very similar to self.analyze_line, but allows the flexibility
        for subclasses to add any other notable info (rather than just a
        PotentialSecret type). e.g. HighEntropyStrings adds their Shannon
        entropy in which they made their decision.

        :type string: str
        :param string: the string to analyze

        :rtype: str
        :returns: descriptive string that fits the format
            <classname>: <returned-value>
        """
        # TODO: Handle multiple secrets on single line.
        results = self.analyze_line(
            string,
            line_num=0,
            filename='does_not_matter',
        )
        if not results:
            return 'False'

        if not self.should_verify:
            return 'True'

        verified_result = VerifiedResult.UNVERIFIED
        for result in results:
            is_verified = self.verify(result.secret_value, string)
            if is_verified != VerifiedResult.UNVERIFIED:
                verified_result = is_verified
                break

        output = {
            VerifiedResult.VERIFIED_FALSE: 'False (verified)',
            VerifiedResult.VERIFIED_TRUE: 'True  (verified)',
            VerifiedResult.UNVERIFIED: 'True  (unverified)',
        }

        return output[verified_result]

    def verify(self, token, context=''):
        """
        To increase accuracy and reduce false positives, plugins can also
        optionally declare a method to verify their status.

        :type token: str
        :param token: secret found by current plugin

        :type context: str
        :param context: lines of context around identified secret

        :rtype: VerifiedResult
        """
        return VerifiedResult.UNVERIFIED

    def is_secret_false_positive(self, token):
        """
        Checks if the input secret is a false-positive according to
        this plugin's heuristics.

        :type token: str
        :param token: secret found by current plugin
        """
        return any(
            func(token)
            for func in self.false_positive_heuristics
        ) if self.false_positive_heuristics else False

    @property
    def __dict__(self):
        return {
            'name': self.__class__.__name__,
        }


class RegexBasedDetector(BasePlugin):
    """Parent class for regular-expression based detectors.

    To create a new regex-based detector, subclass this and set
    `secret_type` with a description and `denylist`
    with a sequence of regular expressions, like:

    class FooDetector(RegexBasedDetector):

        secret_type = "foo"

        denylist = (
            re.compile(r'foo'),
        )
    """
    __metaclass__ = ABCMeta

    @abstractproperty
    def denylist(self):
        raise NotImplementedError

    @staticmethod
    def assign_regex_generator(prefix_regex, secret_keyword_regex, secret_regex):
        """Generate assignment regex
        It reads 3 input parameters, each stands for regex. The return regex would look for
        secret in following format.
        <prefix_regex>(-|_|)<secret_keyword_regex> <assignment> <secret_regex>
        assignment would include =,:,:=,::
        keyname and value supports optional quotes
        """
        begin = r'(?:(?<=\W)|(?<=^))'
        opt_quote = r'(?:"|\'|)'
        opt_open_square_bracket = r'(?:\[|)'
        opt_close_square_bracket = r'(?:\]|)'
        opt_dash_undrscr = r'(?:_|-|)'
        opt_space = r'(?: *)'
        assignment = r'(?:=|:|:=|=>| +|::)'
        return re.compile(
            r'{begin}{opt_open_square_bracket}{opt_quote}{prefix_regex}{opt_dash_undrscr}'
            '{secret_keyword_regex}{opt_quote}{opt_close_square_bracket}{opt_space}'
            '{assignment}{opt_space}{opt_quote}{secret_regex}{opt_quote}'.format(
                begin=begin,
                opt_open_square_bracket=opt_open_square_bracket,
                opt_quote=opt_quote,
                prefix_regex=prefix_regex,
                opt_dash_undrscr=opt_dash_undrscr,
                secret_keyword_regex=secret_keyword_regex,
                opt_close_square_bracket=opt_close_square_bracket,
                opt_space=opt_space,
                assignment=assignment,
                secret_regex=secret_regex,
            ), flags=re.IGNORECASE,
        )

    def analyze_string_content(self, string, line_num, filename):
        output = {}

        for identifier in self.secret_generator(string):
            secret = PotentialSecret(
                self.secret_type,
                filename,
                identifier,
                line_num,
            )
            output[secret] = secret

        return output

    def secret_generator(self, string, *args, **kwargs):
        for regex in self.denylist:
            for match in regex.findall(string):
                yield match
