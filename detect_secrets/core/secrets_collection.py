from __future__ import absolute_import

import codecs
import json
import os
import re
from time import gmtime
from time import strftime

from detect_secrets import VERSION
from detect_secrets.core.log import log
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.common import initialize


class SecretsCollection(object):

    def __init__(
        self,
        plugins=(),
        exclude_files=None,
        exclude_lines=None,
    ):
        """
        :type plugins: tuple of detect_secrets.plugins.base.BasePlugin
        :param plugins: rules to determine whether a string is a secret

        :type exclude_files: str|None
        :param exclude_files: optional regex for ignored paths.

        :type exclude_lines: str|None
        :param exclude_lines: optional regex for ignored lines.

        :type version: str
        :param version: version of detect-secrets that SecretsCollection
            is valid at.
        """
        self.data = {}
        self.plugins = plugins
        self.exclude_files = exclude_files
        self.exclude_lines = exclude_lines
        self.version = VERSION

    @classmethod
    def load_baseline_from_string(cls, string):
        """Initializes a SecretsCollection object from string.

        :type string: str
        :param string: string to load SecretsCollection from.

        :rtype: SecretsCollection
        :raises: IOError
        """
        try:
            return cls.load_baseline_from_dict(json.loads(string))
        except (IOError, ValueError):
            log.error('Incorrectly formatted baseline!')
            raise

    @classmethod
    def load_baseline_from_dict(cls, data):
        """Initializes a SecretsCollection object from dictionary.

        :type data: dict
        :param data: properly formatted dictionary to load SecretsCollection from.

        :rtype: SecretsCollection
        :raises: IOError
        """
        result = SecretsCollection()

        if not all(key in data for key in (
            'plugins_used',
            'results',
        )):
            raise IOError

        # In v0.12.0 `exclude_regex` got replaced by `exclude`
        if not any(key in data for key in (
            'exclude',
            'exclude_regex',
        )):
            raise IOError

        if 'exclude_regex' in data:
            result.exclude_files = data['exclude_regex']
        else:
            result.exclude_files = data['exclude']['files']
            result.exclude_lines = data['exclude']['lines']

        plugins = []
        for plugin in data['plugins_used']:
            plugin_classname = plugin.pop('name')
            plugins.append(initialize.from_plugin_classname(
                plugin_classname,
                exclude_lines_regex=result.exclude_lines,
                **plugin
            ))
        result.plugins = tuple(plugins)

        for filename in data['results']:
            result.data[filename] = {}

            for item in data['results'][filename]:
                secret = PotentialSecret(
                    item['type'],
                    filename,
                    secret='will be replaced',
                    lineno=item['line_number'],
                    is_secret=item.get('is_secret'),
                )
                secret.secret_hash = item['hashed_secret']
                result.data[filename][secret] = secret

        result.version = (
            data['version']
            if 'version' in data
            else '0.0.0'
        )

        return result

    def scan_diff(
        self,
        diff,
        baseline_filename='',
        last_commit_hash='',
        repo_name='',
    ):
        """For optimization purposes, our scanning strategy focuses on looking
        at incremental differences, rather than re-scanning the codebase every time.
        This function supports this, and adds information to self.data.

        :type diff: str
        :param diff: diff string.
                     e.g. The output of `git diff <fileA> <fileB>`

        :type baseline_filename: str
        :param baseline_filename: if there are any baseline secrets, then the baseline
                                  file will have hashes in them. By specifying it, we
                                  can skip this clear exception.

        :type last_commit_hash: str
        :param last_commit_hash: used for logging only -- the last commit hash we saved

        :type repo_name: str
        :param repo_name: used for logging only -- the name of the repo
        """
        # Local imports, so that we don't need to require unidiff for versions of
        # detect-secrets that don't use it.
        from unidiff import PatchSet
        from unidiff.errors import UnidiffParseError

        try:
            patch_set = PatchSet.from_string(diff)
        except UnidiffParseError:  # pragma: no cover
            alert = {
                'alert': 'UnidiffParseError',
                'hash': last_commit_hash,
                'repo_name': repo_name,
            }
            log.error(alert)
            raise

        if self.exclude_files:
            regex = re.compile(self.exclude_files, re.IGNORECASE)

        for patch_file in patch_set:
            filename = patch_file.path
            # If the file matches the exclude_files, we skip it
            if self.exclude_files and regex.search(filename):
                continue

            if filename == baseline_filename:
                continue

            for results, plugin in self._results_accumulator(filename):
                results.update(
                    self._extract_secrets_from_patch(
                        patch_file,
                        plugin,
                        filename,
                    ),
                )

    def scan_file(self, filename, filename_key=None):
        """Scans a specified file, and adds information to self.data

        :type filename: str
        :param filename: full path to file to scan.

        :type filename_key: str
        :param filename_key: key to store in self.data

        :returns: boolean; though this value is only used for testing
        """

        if not filename_key:
            filename_key = filename

        if os.path.islink(filename):
            return False

        try:
            with codecs.open(filename, encoding='utf-8') as f:
                self._extract_secrets_from_file(f, filename_key)

            return True
        except IOError:
            log.warning("Unable to open file: %s", filename)
            return False

    def get_secret(self, filename, secret, type_=None):
        """Checks to see whether a secret is found in the collection.

        :type filename: str
        :param filename: the file to search in.

        :type secret: str
        :param secret: secret hash of secret to search for.

        :type type_: str
        :param type_: type of secret, if known.

        :rtype: PotentialSecret|None
        """
        if filename not in self.data:
            return None

        if type_:
            # Optimized lookup, because we know the type of secret
            # (and therefore, its hash)
            tmp_secret = PotentialSecret(type_, filename, secret='will be overriden')
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

    def format_for_baseline_output(self):
        """
        :rtype: dict
        """
        results = self.json()
        for key in results:
            results[key] = sorted(results[key], key=lambda x: x['line_number'])

        plugins_used = list(map(
            lambda x: x.__dict__,
            self.plugins,
        ))
        plugins_used = sorted(plugins_used, key=lambda x: x['name'])

        return {
            'generated_at': strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()),
            'exclude': {
                'files': self.exclude_files,
                'lines': self.exclude_lines,
            },
            'plugins_used': plugins_used,
            'results': results,
            'version': self.version,
        }

    def _results_accumulator(self, filename):
        """
        :type filename: str
        :param filename: name of file, used as a key to store in self.data

        :yields: (dict, detect_secrets.plugins.base.BasePlugin)
                 Caller is responsible for updating the dictionary with
                 results of plugin analysis.
        """
        file_results = {}

        for plugin in self.plugins:
            yield file_results, plugin

        if not file_results:
            return

        if filename not in self.data:
            self.data[filename] = file_results
        else:
            self.data[filename].update(file_results)

    def _extract_secrets_from_file(self, f, filename):
        """Extract secrets from a given file object.

        :type f:        File object
        :type filename: string
        """
        try:
            log.info("Checking file: %s", filename)

            for results, plugin in self._results_accumulator(filename):
                results.update(plugin.analyze(f, filename))
                f.seek(0)

        except UnicodeDecodeError:
            log.warning("%s failed to load.", filename)

    def _extract_secrets_from_patch(self, f, plugin, filename):
        """Extract secrets from a given patch file object.

        Note that we only want to capture incoming secrets (so added lines).

        :type f: unidiff.patch.PatchedFile
        :type plugin: detect_secrets.plugins.base.BasePlugin
        :type filename: str
        """
        output = {}
        for chunk in f:
            # target_lines refers to incoming (new) changes
            for line in chunk.target_lines():
                if line.is_added:
                    output.update(
                        plugin.analyze_string(
                            line.value,
                            line.target_line_no,
                            filename,
                        ),
                    )

        return output

    def json(self):
        """Custom JSON encoder"""
        output = {}
        for filename in self.data:
            output[filename] = []

            for secret_hash in self.data[filename]:
                tmp = self.data[filename][secret_hash].json()
                del tmp['filename']  # Because filename will map to the secrets

                output[filename].append(tmp)

        return output

    def __str__(self):  # pragma: no cover
        return json.dumps(
            self.json(),
            indent=2,
            sort_keys=True,
        )

    def __getitem__(self, key):  # pragma: no cover
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value
