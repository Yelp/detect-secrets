import pytest

from detect_secrets import main as main_module
from detect_secrets.audit import io
from detect_secrets.audit.common import open_file
from testing.mocks import mock_printer
from testing.mocks import PrinterShim


@pytest.fixture(autouse=True)
def reset_file_cache():
    open_file.cache_clear()


@pytest.fixture(autouse=True)
def printer():
    printer = PrinterShim()
    with mock_printer(main_module, shim=printer), mock_printer(io, shim=printer):
        yield printer
