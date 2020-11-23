import tempfile
import textwrap

import pytest

from detect_secrets.core import scan
from detect_secrets.settings import transient_settings


def test_handles_broken_yaml_gracefully():
    with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
        f.write(
            textwrap.dedent("""
            metadata:
                name: {{ .values.name }}
        """)[1:].encode(),
        )
        f.seek(0)

        assert not list(scan.scan_file(f.name))


@pytest.fixture(autouse=True)
def configure_plugins():
    with transient_settings({
        'plugins_used': [
            {
                'name': 'BasicAuthDetector',
            },
        ],
    }):
        yield
