from __future__ import absolute_import

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection


def potential_secret_factory(type_='type', filename='filename', secret='secret', lineno=1):
    """This is only marginally better than creating PotentialSecret objects directly,
    because of the default values.
    """
    return PotentialSecret(type_, filename, secret, lineno)


def secrets_collection_factory(secrets=None, plugins=(), exclude_files_regex=None):
    """
    :type secrets: list(dict)
    :param secrets: list of params to pass to add_secret.
                    E.g. [ {'secret': 'blah'}, ]

    :type plugins: tuple
    :type exclude_files_regex: str|None

    :rtype: SecretsCollection
    """
    collection = SecretsCollection(
        plugins,
        exclude_files=exclude_files_regex,
    )

    if plugins:
        for plugin in plugins:
            # We don't want to incur network calls during test cases
            plugin.should_verify = False

        collection.plugins = plugins

    # Handle secrets
    if secrets is None:
        return collection

    for kwargs in secrets:
        _add_secret(collection, **kwargs)

    return collection


def _add_secret(collection, type_='type', secret='secret', filename='filename', lineno=1):
    """Utility function to add individual secrets to a SecretCollection.

    :param collection: SecretCollection; will be modified by this function.
    :param filename:   string
    :param secret:     string; secret to add
    :param lineno:     integer; line number of occurring secret
    """
    if filename not in collection.data:  # pragma: no cover
        collection[filename] = {}

    tmp_secret = potential_secret_factory(
        type_=type_,
        filename=filename,
        secret=secret,
        lineno=lineno,
    )
    collection.data[filename][tmp_secret] = tmp_secret
