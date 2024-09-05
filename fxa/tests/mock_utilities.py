from unittest import mock
from binascii import hexlify
from os import urandom


def mocked_core_client():
    client = mock.MagicMock()
    session = mock.MagicMock()
    session.get_identity_assertion.return_value = 'abcd'
    session.fetch_keys.return_value = (b'keyA', b'keyB')
    client.login.return_value = session
    return client


def mocked_oauth_client():
    client = mock.MagicMock()
    client.authorize_token.return_value = hexlify(urandom(32))
    return client
