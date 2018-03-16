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

    def __init__(self, plugins=(), exclude_regex=''):
        """
        :type plugins: tuple of detect_secrets.plugins.BasePlugin
        :param plugins: rules to determine whether a string is a secret

        :type exclude_regex: str
        :param exclude_regex: for optional regex for ignored paths.
        """
        self.data = {}
        self.plugins = plugins
        self.exclude_regex = exclude_regex

    @classmethod
    def load_baseline_from_file(cls, filename):
        """Initialize a SecretsCollection object from file.

        :param filename: string; name of file to load
        :returns: SecretsCollection
        :raises: IOError
        """
        try:
            with codecs.open(filename, encoding='utf-8') as f:
                baseline_string = f.read()

        except (IOError, UnicodeDecodeError):
            CustomLogObj.getLogger().error(
                "Unable to open baseline file: %s.", filename
            )

            raise

        return cls.load_baseline_from_string(baseline_string)

    @classmethod
    def load_baseline_from_string(cls, string):
        """Initializes a SecretsCollection object from string.

        :type string: str
        :param string: string to load SecretsCollection from.

        :rtype: SecretsCollection
        :raises: IOError
        """
        try:
            return cls._load_baseline_from_dict(json.loads(string))
        except (IOError, ValueError):
            CustomLogObj.getLogger().error('Incorrectly formatted baseline!')
            raise

    @classmethod
    def _load_baseline_from_dict(cls, data):
        """Initializes a SecretsCollection object from dictionary.

        :type data: dict
        :param data: properly formatted dictionary to load SecretsCollection from.

        :rtype: SecretsCollection
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

    def scan_diff(
            self,
            diff,
            baseline_filename='',
            last_commit_hash='',
            repo_name=''
    ):
        """For optimization purposes, our scanning strategy focuses on looking
        at incremental differences, rather than re-scanning the codebase every time.
        This function supports this, and adds information to self.data.

        :type diff: str
        :param diff: diff string.
                     Eg. The output of `git diff <fileA> <fileB>`

        :type baseline_filename: str
        :param baseline_filename: if there are any baseline secrets, then the baseline
                                  file will have hashes in them. By specifying it, we
                                  can skip this clear exception.

        :type last_commit_hash: str
        :param last_commit_hash: used for logging only -- the last commit hash we saved

        :type repo_name: str
        :param repo_name: used for logging only -- the name of the repo
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

        if self.exclude_regex:
            regex = re.compile(self.exclude_regex, re.IGNORECASE)

        for patch_file in patch_set:
            filename = patch_file.path
            # If the file matches the exclude_regex, we skip it
            if self.exclude_regex and regex.search(filename):
                continue

            if filename == baseline_filename:
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

        :type filename: str
        :param filename: full path to file to scan.

        :type filename_key: str
        :param filename_key: key to store in self.data

        :returns: boolean; though this value is only used for testing
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

        :type filename: str
        :param filename: the file to search in.

        :type secret: str
        :param secret: secret hash of secret to search for.

        :type typ: str
        :param [typ]: type of secret, if known.

        :rtype: PotentialSecret|None
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

        :type f:        File object
        :type filename: string
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

    def format_for_baseline_output(self):
        """
        :rtype: dict
        """
        results = self.json()
        for key in results:
            results[key] = sorted(results[key], key=lambda x: x['line_number'])

        return {
            'generated_at': strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()),
            'exclude_regex': self.exclude_regex,
            'results': results,
        }

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
