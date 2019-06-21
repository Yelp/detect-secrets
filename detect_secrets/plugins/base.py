import re
from abc import ABCMeta
from abc import abstractmethod
from abc import abstractproperty

from .common.constants import ALLOWLIST_REGEXES
from .common.filters import is_false_positive
from detect_secrets.core.code_snippet import CodeSnippetHighlighter
from detect_secrets.core.constants import VerifiedResult
from detect_secrets.core.potential_secret import PotentialSecret


# NOTE: In this whitepaper (Section V-D), it suggests that there's an
#       80% chance of finding a multi-factor secret (e.g. username +
#       password) within five lines of context, before and after a secret.
#
#       This number can be tweaked if desired, at the cost of performance.
#
#       https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
LINES_OF_CONTEXT = 5


class BasePlugin(object):
    """This is an abstract class to define Plugins API"""

    __metaclass__ = ABCMeta

    secret_type = None

    def __init__(self, exclude_lines_regex=None, should_verify=False, **kwargs):
        """
        :type exclude_lines_regex: str|None
        :param exclude_lines_regex: optional regex for ignored lines.

        :type should_verify: bool
        """
        if not self.secret_type:
            raise ValueError('Plugins need to declare a secret_type.')

        self.exclude_lines_regex = None
        if exclude_lines_regex:
            self.exclude_lines_regex = re.compile(exclude_lines_regex)

        self.should_verify = should_verify

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
        for line_num, line in enumerate(file.readlines(), start=1):
            results = self.analyze_string(line, line_num, filename)
            if not self.should_verify:
                potential_secrets.update(results)
                continue

            filtered_results = {}
            for result in results:
                snippet = CodeSnippetHighlighter().get_code_snippet(
                    filename,
                    result.lineno,
                    lines_of_context=LINES_OF_CONTEXT,
                )

                is_verified = self.verify(result.secret_value, content=str(snippet))
                if is_verified != VerifiedResult.UNVERIFIED:
                    result.is_verified = True

                if is_verified != VerifiedResult.VERIFIED_FALSE:
                    filtered_results[result] = result

            potential_secrets.update(filtered_results)

        return potential_secrets

    def analyze_string(self, string, line_num, filename):
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        NOTE: line_num and filename are used for PotentialSecret creation only.
        """
        if (
            any(
                allowlist_regex.search(string) for allowlist_regex in ALLOWLIST_REGEXES
            )

            or (
                self.exclude_lines_regex and
                self.exclude_lines_regex.search(string)
            )
        ):
            return {}

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

        NOTE: line_num and filename are used for PotentialSecret creation only.
        """
        raise NotImplementedError

    @abstractmethod
    def secret_generator(self, string, *args, **kwargs):
        """Flags secrets in a given string, and yields the raw secret value.
        Used in self.analyze_string for PotentialSecret creation.

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

        This is very similar to self.analyze_string, but allows the flexibility
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
        results = self.analyze_string(string, 0, 'does_not_matter')
        if not results:
            return 'False'

        if not self.should_verify:
            return 'True'

        verified_result = VerifiedResult.UNVERIFIED
        for result in results:
            is_verified = self.verify(result.secret_value)
            if is_verified != VerifiedResult.UNVERIFIED:
                verified_result = is_verified
                break

        output = {
            VerifiedResult.VERIFIED_FALSE: 'False (verified)',
            VerifiedResult.VERIFIED_TRUE: 'True  (verified)',
            VerifiedResult.UNVERIFIED: 'True  (unverified)',
        }

        return output[verified_result]

    def verify(self, token, content=''):
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

    @property
    def __dict__(self):
        return {
            'name': self.__class__.__name__,
        }


class RegexBasedDetector(BasePlugin):
    """Base class for regular-expression based detectors.

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
    def secret_type(self):
        raise NotImplementedError

    @abstractproperty
    def denylist(self):
        raise NotImplementedError

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
                if is_false_positive(match):
                    continue

                yield match
