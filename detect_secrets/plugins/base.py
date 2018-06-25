from abc import ABCMeta
from abc import abstractmethod


class BasePlugin(object):
    """This is an abstract class to define Plugins API"""

    __metaclass__ = ABCMeta
    secret_type = None

    def __init__(self, **kwargs):
        if not self.secret_type:
            raise ValueError('Plugins need to declare a secret_type.')

    def analyze(self, file, filename):  # pragma: no cover
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
    def analyze_string(self, string, line_num, filename):   # pragma: no cover
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        NOTE: line_num and filename are used for PotentialSecret creation only.
        """
        pass

    @abstractmethod
    def secret_generator(self, string):  # pragma: no cover
        """Flags secrets in a given string, and yields the raw secret value.
        Used in self.analyze_string for PotentialSecret creation.

        :type string: str
        :param string: the secret to scan
        """
        pass

    @property
    def __dict__(self):
        return {
            'name': self.__class__.__name__,
        }
