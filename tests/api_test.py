from git import Repo
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.api import load_plugin_by_name
from detect_secrets.api import scan_string
from detect_secrets.api import scan_file
from detect_secrets.api import scan_git_repository


class TestApi:

    def test_load_plugin_by_name(self):
        plugin_name = "AWSKeyDetector"
        plugin = load_plugin_by_name(plugin_name)
        assert plugin.__class__.__name__ == plugin_name

    def test_scan_string_with_specified_plugin(self):
        string = "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        plugin_name = "AWSKeyDetector"

        return_value = {plugin_name: ["AKIAIOSFODNN7EXAMPLE"]}

        result = scan_string(string, plugin_name)
        assert result == {"AWSKeyDetector": ["AKIAIOSFODNN7EXAMPLE"]}

    def test_scan_file_for_secrets(self):
        plugin_name = "AWSKeyDetector"
        return_value = [
            {
                "Line 1": {
                    "AWSKeyDetector": ["AKIAIOSFODNN7EXAMPLE"],
                    "Base64HighEntropyString": ["AKIAIOSFODNN7EXAMPLE"],
                    "KeywordDetector": ["AKIAIOSFODNN7EXAMPLE"],
                }
            }
        ]

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'\nNo secrets here")
            temp_file_path = temp_file.name

        result = scan_file(temp_file_path, plugin_name)
        assert result == {"Line 1": {"AWSKeyDetector": ["AKIAIOSFODNN7EXAMPLE"]}}

    def test_scan_git_repository(self):
        repo_path = tempfile.mkdtemp()
        # os.makedirs(os.path.join(repo_path, '.git'))
        repo = Repo.init(repo_path)
        with open(f"{repo_path}/test-file.txt", "w") as temp_file:
            temp_file.write("AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'")

        result = scan_git_repository(repo_path, "AWSKeyDetector", scan_all_files=True)
        assert result == {
            f"{repo_path}/test-file.txt": {
                "Line 1": {"AWSKeyDetector": ["AKIAIOSFODNN7EXAMPLE"]}
            }
        }
