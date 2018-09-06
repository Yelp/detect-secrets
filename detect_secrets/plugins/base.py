from abc import ABCMeta
from abc import abstractmethod


class BasePlugin(object):
    """This is an abstract class to define Plugins API"""

    __metaclass__ = ABCMeta
    secret_type = None

    def __init__(self, **kwargs):
        if not self.secret_type:
            raise ValueError('Plugins need to declare a secret_type.')

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
            secrets = self.analyze_string(line, line_num, filename)
            potential_secrets.update(secrets)

        return potential_secrets

    @abstractmethod
    def analyze_string(self, string, line_num, filename):
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        NOTE: line_num and filename are used for PotentialSecret creation only.
        """
        raise NotImplementedError

    @abstractmethod
    def secret_generator(self, string):
        """Flags secrets in a given string, and yields the raw secret value.
        Used in self.analyze_string for PotentialSecret creation.

        :type string: str
        :param string: the secret to scan
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
        else:
            return 'True'

    @property
    def __dict__(self):
        return {
            'name': self.__class__.__name__,
        }
