class BasePlugin(object):
    """This is an abstract class to define Plugins API"""

    def __init__(self, *args):
        pass

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

    def analyze_string(self, string, line_num, filename):   # pragma: no cover
        """
        :param string:    string; the line to analyze
        :param line_num:  integer; line number that is currently being analyzed
        :param filename:  string; name of file being analyzed
        :returns:         dictionary

        NOTE: line_num and filename are used for PotentialSecret creation only.
        """

        raise NotImplementedError(
            '%s needs to implement analyze_string()' % self.__class__.__name__
        )

    @property
    def __dict__(self):
        return {
            'name': self.__class__.__name__,
        }
