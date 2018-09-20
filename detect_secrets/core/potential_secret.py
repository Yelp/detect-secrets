import hashlib


class PotentialSecret(object):
    """This custom data type represents a string found, matching the
    plugin rules defined in SecretsCollection, that has the potential
    to be a secret that we actually care about.

    "Potential" is the operative word here, because of the nature of
    false positives.

    We use this custom class so that we can more easily generate data
    structures and do object-based comparisons with other PotentialSecrets,
    without actually knowing what the secret is.
    """

    def __init__(
        self,
        typ,
        filename,
        secret,
        lineno=0,
        is_secret=None,
    ):
        """
        :type typ: str
        :param typ: human-readable secret type, defined by the plugin
                    that generated this PotentialSecret.
                    e.g. "High Entropy String"

        :type filename: str
        :param filename: name of file that this secret was found

        :type secret: str
        :param secret: the actual secret identified

        :type lineno: int
        :param lineno: location of secret, within filename.
                       Merely used as a reference for easy triage.

        :type is_secret: bool|None
        :param is_secret: whether or not the secret is a true- or false- positive
        """
        self.type = typ
        self.filename = filename
        self.lineno = lineno
        self.secret_hash = self.hash_secret(secret)
        self.is_secret = is_secret

        # If two PotentialSecrets have the same values for these fields,
        # they are considered equal. Note that line numbers aren't included
        # in this, because line numbers are subject to change.
        self.fields_to_compare = ['filename', 'secret_hash', 'type']

    @staticmethod
    def hash_secret(secret):
        """This offers a way to coherently test this class,
        without mocking self.secret_hash.

        :type secret: string
        :rtype: string
        """
        return hashlib.sha1(secret.encode('utf-8')).hexdigest()

    def json(self):
        """Custom JSON encoder"""
        attributes = {
            'type': self.type,
            'filename': self.filename,
            'line_number': self.lineno,
            'hashed_secret': self.secret_hash,
        }

        if self.is_secret is not None:
            attributes['is_secret'] = self.is_secret

        return attributes

    def __eq__(self, other):
        return all(
            getattr(self, field) == getattr(other, field)
            for field in self.fields_to_compare
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(
            tuple(
                getattr(self, x)
                for x in self.fields_to_compare
            ),
        )

    def __str__(self):  # pragma: no cover
        return (
            "Secret Type: %s\n"
            "Location:    %s:%d\n"
        ) % (
            self.type,
            self.filename, self.lineno,
        )
