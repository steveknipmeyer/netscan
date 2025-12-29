import pytest

from netscan.network import NetworkDetectionError, resolve_hostname, get_network_cidr


def test_get_network_cidr_unknown_interface():
    with pytest.raises(NetworkDetectionError):
        get_network_cidr("fake0")


def test_resolve_hostname_loopback():
    # Hostname lookup for loopback should either resolve or return None without raising.
    result = resolve_hostname("127.0.0.1")
    assert result is None or isinstance(result, str)
