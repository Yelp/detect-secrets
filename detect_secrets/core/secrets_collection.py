#!/usr/bin/python
from __future__ import absolute_import

import codecs
import json
import os
import re
from time import gmtime
from time import strftime

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from detect_secrets.core.log import CustomLog
from detect_secrets.core.potential_secret import PotentialSecret


CustomLogObj = CustomLog()


class SecretsCollection(object):

    def __init__(self, plugins=()):
        """
        :param plugins: tuple of plugins to determine secrets
        """
        self.data = {}
        self.plugins = plugins
        self.exclude_regex = ''

    @classmethod
    def load_from_file(cls, filename):
        """Initialize a SecretsCollection object from file.

        :param filename: string; name of file to load
        :returns: SecretsCollection
        :raises: IOError
        """
        try:
            with codecs.open(filename, encoding='utf-8') as f:
                baseline = json.loads(f.read())

        except (IOError, UnicodeDecodeError):
            CustomLogObj.getLogger().error(
                "Unable to open baseline file: %s.", filename
            )

            raise

        try:
            return cls.load_from_dict(baseline)
        except IOError:
            CustomLogObj.getLogger().error('Incorrectly formatted baseline!')
            raise

    @classmethod
    def load_from_string(cls, string):
        """Initializes a SecretsCollection object from string

        :param string: string; string to load SecretsCollection from.
        :returns: SecretsCollection
        :raises: IOError
        """
        try:
            return cls.load_from_dict(json.loads(string))
        except (IOError, ValueError):
            CustomLogObj.getLogger().error('Incorrectly formatted baseline!')
            raise

    @classmethod
    def load_from_dict(cls, data):
        """Initializes a SecretsCollection object from dictionary.

        :param data: dict; properly formatted dictionary to load SecretsCollection from.
        :returns: SecretsCollection
        :raises: IOError
        """
        result = SecretsCollection()
        if 'results' not in data or 'exclude_regex' not in data:
            raise IOError

        for filename in data['results']:
            result.data[filename] = {}

            for item in data['results'][filename]:
                secret = PotentialSecret(
                    item['type'],
                    filename,
                    item['line_number'],
                    'will be replaced'
                )
                secret.secret_hash = item['hashed_secret']
                result.data[filename][secret] = secret

        result.exclude_regex = data['exclude_regex']

        return result

    def load_from_diff(self, diff, exclude_regex='', baseline_file='', last_commit_hash='', repo_name=''):
        """Initializes a SecretsCollection object from diff.
        Not a classmethod, since it needs the list of self.plugins for secret scanning.

        :param diff: string; diff string
        :param exclude_regex: string; a regular expression of what files to skip over
        :param baseline_file: string or None; the baseline_file of the repo, to skip over since it contains hashes
        :param last_commit_hash: string; used for logging only -- the last hash we saved
        :param repo_name: string; used for logging only -- the name of the repo
        """
        try:
            patch_set = PatchSet.from_string(diff)
        except UnidiffParseError:  # pragma: no cover
            alert = {
                'alert': 'UnidiffParseError',
                'hash': last_commit_hash,
                'repo_name': repo_name,
            }
            CustomLogObj.getLogger().error(alert)
            raise

        if exclude_regex:
            regex = re.compile(exclude_regex, re.IGNORECASE)

        for patch_file in patch_set:
            filename = patch_file.path
            # If the file matches the exclude_regex, we skip it
            if exclude_regex and regex.search(filename):
                continue
            # Skip over the baseline_file, because it will have hashes in it.
            if filename == baseline_file:
                continue

            # We only want to capture incoming secrets (so added lines)
            # Terminology:
            #  - A "hunk" is a patch chunk in the patch_file
            #  - `target_lines` is from the incoming changes
            results = {}
            for hunk in patch_file:
                for line in hunk.target_lines():
                    if line.is_added:
                        for plugin in self.plugins:
                            results.update(plugin.analyze_string(
                                line.value,
                                line.target_line_no,
                                filename
                            ))

            if not results:
                continue

            if filename not in self.data:
                self.data[filename] = results
            else:
                self.data[filename].update(results)

    def scan_file(self, filename, filename_key=None):
        """Scans a specified file, and adds information to self.data

        :param filename:     string; full path to file to scan.
        :param filename_key: string; key to store in self.data
        :returns: boolean; used for testing
        """

        if filename_key is None:
            filename_key = filename

        if os.path.islink(filename):
            return False

        try:
            with codecs.open(filename, encoding='utf-8') as f:
                self._extract_secrets(f, filename_key)

            return True

        except IOError:
            CustomLogObj.getLogger().warning("Unable to open file: %s", filename)
            return False

    def get_secret(self, filename, secret, typ=None):
        """Checks to see whether a secret is found in the collection.

        :param filename: string; which file to search in.
        :param secret:   string; secret hash of secret to search for.
        :param [typ]:    string; type of secret, if known.
        :returns:        PotentialSecret or None
        """
        if filename not in self.data:
            return None

        if typ:
            # Optimized lookup, because we know the type of secret
            # (and therefore, its hash)
            tmp_secret = PotentialSecret(typ, filename, 0, 'will be overriden')
            tmp_secret.secret_hash = secret

            if tmp_secret in self.data[filename]:
                return self.data[filename][tmp_secret]

            return None

        # NOTE: We can only optimize this, if we knew the type of secret.
        # Otherwise, we need to iterate through the set and find out.
        for obj in self.data[filename]:
            if obj.secret_hash == secret:
                return obj

        return None

    def _extract_secrets(self, f, filename):
        """Extract the secrets from a given file object.

        :param f:        File object
        :param filename: string
        """
        log = CustomLogObj.getLogger()
        try:
            log.info("Checking file: %s", filename)

            results = {}
            for plugin in self.plugins:
                results.update(plugin.analyze(f, filename))
                f.seek(0)

            if not results:
                return

            if filename not in self.data:
                self.data[filename] = results
            else:
                self.data[filename].update(results)

        except UnicodeDecodeError:
            log.warning("%s failed to load.", filename)

    def output_baseline(self, exclude_regex=''):
        """Formats the SecretsCollection for baseline output.

        :param [exclude_regex]: string; for optional regex string for ignored paths.
        :returns: json-formatted string.
        """
        if not exclude_regex:
            exclude_regex = ''

        results = self.json()
        for key in results:
            results[key] = sorted(results[key], key=lambda x: x['line_number'])

        obj = {
            'generated_at': strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()),
            'exclude_regex': exclude_regex,
            'results': results,
        }

        return json.dumps(obj, indent=2)

    def json(self):
        """Custom JSON encoder"""
        output = {}
        for filename in self.data:
            output[filename] = []

            for secret_hash in self.data[filename]:
                tmp = self.data[filename][secret_hash].json()
                del tmp['filename']     # not necessary

                output[filename].append(tmp)

        return output

    def get_authors(self, repo):
        """Parses git blame output to retrieve author information.

        :param: object; An object representing a repository.

        :returns: set of all authors
        """
        authors = set()

        for filename in self.data:
            # Loop through all PotentialSecret's
            for item in self.data[filename]:
                blame = repo.get_blame(
                    item.lineno,
                    filename,
                ).decode('utf-8').split()

                index_of_mail = blame.index('author-mail')
                email = blame[index_of_mail + 1]  # <khock@yelp.com>
                index_of_at = email.index('@')
                authors.add(email[1:index_of_at])  # Skip the <, end at @

        return authors

    def __str__(self):  # pragma: no cover
        return json.dumps(self.json(), indent=2)

    def __getitem__(self, key):  # pragma: no cover
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
