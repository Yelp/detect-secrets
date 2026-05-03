"""Regression tests for the `--security-team` CLI flag.

Issue #436 / PR ___: the legacy `DETECT_SECRETS_SECURITY_TEAM` env var was
hard to set via pre-commit (which has no first-class support for env vars),
so we plumb the same value through a CLI argument that takes precedence.
"""
from unittest import mock

import pytest

from detect_secrets.pre_commit_hook import DEFAULT_SECURITY_TEAM_CONTACT
from detect_secrets.pre_commit_hook import main
from detect_secrets.pre_commit_hook import pretty_print_diagnostics
from detect_secrets.pre_commit_hook import resolve_security_team_contact
from detect_secrets.settings import transient_settings


@pytest.fixture(autouse=True)
def configure_settings():
    with transient_settings({
        'plugins_used': [{'name': 'Base64HighEntropyString', 'limit': 4.5}],
    }):
        yield


class TestResolveSecurityTeamContact:
    def test_cli_value_wins(self, monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_SECURITY_TEAM', 'env-team')
        assert resolve_security_team_contact('cli-team') == 'cli-team'

    def test_env_var_used_when_cli_absent(self, monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_SECURITY_TEAM', 'env-team')
        assert resolve_security_team_contact(None) == 'env-team'

    def test_default_when_neither_set(self, monkeypatch):
        monkeypatch.delenv('DETECT_SECRETS_SECURITY_TEAM', raising=False)
        assert resolve_security_team_contact(None) == DEFAULT_SECURITY_TEAM_CONTACT

    def test_empty_string_cli_value_falls_back(self, monkeypatch):
        """An empty --security-team must not silently produce an empty contact."""
        monkeypatch.setenv('DETECT_SECRETS_SECURITY_TEAM', 'env-team')
        assert resolve_security_team_contact('') == 'env-team'


class TestPrettyPrintDiagnostics:
    def test_uses_cli_value(self, capsys, monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_SECURITY_TEAM', 'env-team-should-be-overridden')
        from detect_secrets.core.secrets_collection import SecretsCollection
        secrets = _collection_with_one_secret()
        pretty_print_diagnostics(secrets, security_team='#infosec on Slack')
        captured = capsys.readouterr().out
        assert '#infosec on Slack' in captured
        assert 'env-team-should-be-overridden' not in captured

    def test_falls_back_to_env(self, capsys, monkeypatch):
        monkeypatch.setenv('DETECT_SECRETS_SECURITY_TEAM', '#legacy-channel')
        secrets = _collection_with_one_secret()
        pretty_print_diagnostics(secrets)
        captured = capsys.readouterr().out
        assert '#legacy-channel' in captured

    def test_default_when_nothing_set(self, capsys, monkeypatch):
        monkeypatch.delenv('DETECT_SECRETS_SECURITY_TEAM', raising=False)
        secrets = _collection_with_one_secret()
        pretty_print_diagnostics(secrets)
        captured = capsys.readouterr().out
        # textwrap may wrap the default contact across a newline so check for
        # the leading distinctive token rather than the literal phrase.
        assert '#security' in captured


class TestEndToEnd:
    """Ensure the CLI flag actually flows through main() to the printer."""

    def test_cli_flag_appears_in_output(self, capsys, monkeypatch):
        monkeypatch.delenv('DETECT_SECRETS_SECURITY_TEAM', raising=False)
        rc = main([
            'test_data/files/file_with_secrets.py',
            '--security-team', '#secops',
        ])
        assert rc == 1  # secrets blocked
        captured = capsys.readouterr().out
        assert '#secops' in captured
        assert DEFAULT_SECURITY_TEAM_CONTACT not in captured


def _collection_with_one_secret():
    from detect_secrets.core.secrets_collection import SecretsCollection
    secrets = SecretsCollection()
    secrets.scan_file('test_data/files/file_with_secrets.py')
    return secrets
