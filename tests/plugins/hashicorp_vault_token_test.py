import pytest

from detect_secrets.plugins.hashicorp_vault_token import HashiCorpVaultTokenDetector


class TestHashiCorpVaultTokenDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('hvs.wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', True),
            ('hvs.wWPw5k4aXcaT', False),
            ('HideMyTokenhvs.wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', True),
            ('s.wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx', True),
            ('MyClass.atLeast24CharactersField', False),
            ('MyClas s.atLeast24CharactersField', True),
            ('foo', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = HashiCorpVaultTokenDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
