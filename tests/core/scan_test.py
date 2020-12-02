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


def test_handles_binary_files_gracefully():
    # NOTE: This suffix needs to be something that isn't in the known file types, as determined
    # by `detect_secrets.util.filetype.determine_file_type`.
    with tempfile.NamedTemporaryFile(suffix='.woff2') as f:
        f.write(b'\x86')
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
