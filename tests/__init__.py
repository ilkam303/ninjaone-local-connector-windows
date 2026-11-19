"""Suite-level network guard (hard constraint 6).

Imported before any test runs (unittest discovers the package). Replaces the
socket layer so ANY attempt to reach a real host — DNS lookup or TCP connect —
fails loudly with AssertionError instead of silently touching the live
NinjaOne tenant. The entire suite runs offline against mocks; the guard itself
is exercised by tests/test_api.py.
"""

import socket

_GUARD_MESSAGE = ("TEST NETWORK GUARD: a test attempted real network access ({}). "
                  "All tests must run offline against mocks.")


class GuardedSocket(socket.socket):
    def connect(self, address):
        raise AssertionError(_GUARD_MESSAGE.format(address))

    def connect_ex(self, address):
        raise AssertionError(_GUARD_MESSAGE.format(address))


def _blocked_getaddrinfo(host, *args, **kwargs):
    raise AssertionError(_GUARD_MESSAGE.format(host))


def _blocked_create_connection(address, *args, **kwargs):
    raise AssertionError(_GUARD_MESSAGE.format(address))


socket.socket = GuardedSocket
socket.getaddrinfo = _blocked_getaddrinfo
socket.create_connection = _blocked_create_connection
