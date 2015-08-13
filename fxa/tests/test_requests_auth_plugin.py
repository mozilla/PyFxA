from binascii import hexlify
import mock
from os import urandom

from fxa.cache import MemoryCache
from fxa.plugins.requests import FxABrowserIDAuth, FxABearerTokenAuth
from fxa.tests.utils import unittest


class Request(object):
    def __init__(self):
        self.method = 'GET'
        self.body = ''
        self.url = 'http://www.example.com'
        self.headers = {'Content-Type': 'application/json'}


def mocked_core_client():
    client = mock.MagicMock()
    session = mock.MagicMock()
    session.get_identity_assertion.return_value = 'abcd'
    session.fetch_keys.return_value = ('keyA'.encode('utf-8'),
                                       'keyB'.encode('utf-8'))
    client.login.return_value = session
    return client


def mocked_oauth_client():
    client = mock.MagicMock()
    client.authorize_token.return_value = hexlify(urandom(32))
    return client


class TestFxABrowserIDAuth(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestFxABrowserIDAuth, self).__init__(*args, **kwargs)
        self.auth = FxABrowserIDAuth(email="test@restmail.com",
                                     password="this is not a password",
                                     with_client_state=True,
                                     server_url="http://localhost:5000")

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_audience_is_parsed(self, client_patch):
        self.auth(Request())
        self.assertEquals(self.auth.audience, "http://www.example.com/")

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_server_url_is_passed_to_client(self, client_patch):
        self.auth(Request())
        client_patch.assert_called_with(server_url="http://localhost:5000")

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_header_are_set_to_request(self, client_patch):
        r = self.auth(Request())
        self.assertIn('Authorization', r.headers)
        self.assertTrue(r.headers['Authorization'].startswith("BrowserID"),
                        "Authorization headers does not start with BrowserID")
        self.assertIn('X-Client-State', r.headers)

        client_patch.assert_called_with(
            server_url="http://localhost:5000")

        client_patch.return_value.login.assert_called_with(
            "test@restmail.com",
            "this is not a password",
            keys=True)

        client_patch.return_value.login.return_value. \
            get_identity_assertion.assert_called_with(
                audience="http://www.example.com/", duration=3600)

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_client_state_not_set_by_default(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        r = auth(Request())
        self.assertNotIn('X-Client-State', r.headers)

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_memory_cache_is_set_by_default(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        assert type(auth.cache) is MemoryCache

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    def test_it_works_with_no_cache(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000",
                                cache=False)
        assert not auth.cache
        r = auth(Request())
        self.assertIn('Authorization', r.headers)


class TestFxABearerTokenAuth(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestFxABearerTokenAuth, self).__init__(*args, **kwargs)
        self.auth = FxABearerTokenAuth(
            email="test@restmail.com",
            password="this is not a password",
            account_server_url="https://accounts.com/auth/v1",
            oauth_server_url="https://oauth.com/oauth/v1")

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.plugins.requests.oauth.Client',
                return_value=mocked_oauth_client())
    def test_header_are_set_to_request(self, oauth_client_patch,
                                       core_client_patch):
        r = self.auth(Request())
        self.assertIn('Authorization', r.headers)
        self.assertTrue(r.headers['Authorization'].startswith("Bearer"),
                        "Authorization headers does not start with Bearer")

        core_client_patch.assert_called_with(
            server_url="https://accounts.com/auth/v1")
        oauth_client_patch.assert_called_with(
            server_url="https://oauth.com/oauth/v1")

        core_client_patch.return_value.login.return_value. \
            get_identity_assertion.assert_called_with(
                "https://oauth.com/")

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.plugins.requests.oauth.Client',
                return_value=mocked_oauth_client())
    def test_memory_cache_is_set_by_default(self, oauth_client_patch,
                                            core_client_patch):
        assert type(self.auth.cache) is MemoryCache

    @mock.patch('fxa.plugins.requests.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.plugins.requests.oauth.Client',
                return_value=mocked_oauth_client())
    def test_it_works_with_no_cache(self, oauth_client_patch,
                                    core_client_patch):
        auth = FxABearerTokenAuth(
            email="test@restmail.com",
            password="this is not a password",
            account_server_url="https://accounts.com/auth/v1",
            oauth_server_url="https://oauth.com/oauth/v1", cache=False)
        assert not auth.cache
        r = auth(Request())
        self.assertIn('Authorization', r.headers)
