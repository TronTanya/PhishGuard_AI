import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class NetworkAccessError(AssertionError):
    pass


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if any code attempts DNS resolution or a socket connection."""

    def blocked(*args, **kwargs):
        raise NetworkAccessError("Попытка сетевого запроса во время анализа")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
