import pytest

from detect_secrets.plugins.github_token import GitHubTokenDetector
from detect_secrets.plugins.gitlab_token import GitLabTokenDetector


@pytest.mark.parametrize(
    'logic,token',
    [
        (GitHubTokenDetector(), 'ghp_' + 'ExampleToken' * 3),
        (GitLabTokenDetector(), 'glpat-exampleToken0123456789ab'),
        (GitLabTokenDetector(), 'glcbt-exampleToken0123456789ab'),
    ],
)
def test_secret_value_is_full_token(logic, token):
    output = logic.analyze_line(filename='mock_filename', line=token)
    assert [secret.secret_value for secret in output] == [token]
