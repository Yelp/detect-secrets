#!/usr/bin/python
import hashlib


class PotentialSecret(object):

    def __init__(self, typ, filename, lineno, secret):
        """
        :param typ:      string; human-readable typing of what makes this
                         secret identified a "potential secret"
        :param filename: string; name of file that this potential secret was found
        :param lineno:   integer; location of secret
        :param secret:   string; the secret identified
        """
        self.type = typ
        self.filename = filename
        self.lineno = lineno
        self.secret_hash = self.hash_secret(secret)
        # This is set in set_authors in SecretsCollection
        self.author = None

        # If two PotentialSecrets have the same values for these fields,
        # they are considered equal.
        self.fields_to_compare = ['filename', 'secret_hash', 'type']

    @classmethod
    def hash_secret(self, secret):
        """
        :param secret: string
        :returns: string
        """
        return hashlib.sha1(secret.encode('utf-8')).hexdigest()

    def json(self):
        """Custom JSON encoder"""
        attributes = {
            'type': self.type,
            'filename': self.filename,
            'line_number': self.lineno,
            'hashed_secret': self.secret_hash
        }
        if self.author:
            attributes['author'] = self.author
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
            tuple([getattr(self, x) for x in self.fields_to_compare])
        )

    def __str__(self):  # pragma: no cover
        return (
            "Secret Type: %s\n"
            "Location:    ./%s:%d\n"
            # "Hash:        %s\n"
        ) % (
            self.type,
            self.filename, self.lineno,
            # self.secret_hash
        )
