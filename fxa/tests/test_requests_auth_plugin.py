from fxa.cache import MemoryCache
from fxa.plugins.requests import (
    FxABrowserIDAuth, FxABearerTokenAuth, get_cache_key, DEFAULT_CACHE_EXPIRY)
from fxa.tests.utils import unittest
from fxa.tests.mock_utilities import (
    mock, mocked_core_client, mocked_oauth_client)


class Request(object):
    def __init__(self):
        self.method = 'GET'
        self.body = ''
        self.url = 'http://www.example.com'
        self.headers = {'Content-Type': 'application/json'}


class TestFxABrowserIDAuth(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestFxABrowserIDAuth, self).__init__(*args, **kwargs)
        self.auth = FxABrowserIDAuth(email="test@restmail.com",
                                     password="this is not a password",
                                     with_client_state=True,
                                     server_url="http://localhost:5000")

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_audience_is_parsed(self, client_patch):
        self.auth(Request())
        self.assertEquals(self.auth.audience, "http://www.example.com/")

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_server_url_is_passed_to_client(self, client_patch):
        self.auth(Request())
        client_patch.assert_called_with(server_url="http://localhost:5000")

    @mock.patch('fxa.core.Client',
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

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_client_state_not_set_by_default(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        r = auth(Request())
        self.assertNotIn('X-Client-State', r.headers)

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_memory_cache_is_set_by_default(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        assert type(auth.cache) is MemoryCache
        self.assertEqual(auth.cache.ttl, DEFAULT_CACHE_EXPIRY - 1)

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_memory_cache_is_used(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        assert type(auth.cache) is MemoryCache
        self.assertEqual(auth.cache.ttl, DEFAULT_CACHE_EXPIRY - 1)

        # First call should set the cache value
        auth(Request())
        self.assertEquals(client_patch.return_value.login.return_value.
                          get_identity_assertion.call_count, 1)
        # Second call should use the cache value
        auth(Request())
        self.assertEquals(client_patch.return_value.login.return_value.
                          get_identity_assertion.call_count, 1)

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_it_works_with_cache_deactivated(self, client_patch):
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
            client_id="53210789456",
            account_server_url="https://accounts.com/auth/v1",
            oauth_server_url="https://oauth.com/oauth/v1")

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.oauth.Client',
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

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.oauth.Client',
                return_value=mocked_oauth_client())
    def test_memory_cache_is_set_by_default(self, oauth_client_patch,
                                            core_client_patch):
        assert type(self.auth.cache) is MemoryCache
        self.assertEqual(self.auth.cache.ttl, DEFAULT_CACHE_EXPIRY)

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.oauth.Client',
                return_value=mocked_oauth_client())
    def test_memory_cache_is_used(self, oauth_client_patch,
                                  core_client_patch):
        # First call should set the cache value
        self.auth(Request())
        self.assertEquals(core_client_patch.call_count, 1)
        self.assertEquals(oauth_client_patch.call_count, 1)

        # Second call should use the cache value
        self.auth(Request())
        self.assertEquals(core_client_patch.call_count, 1)
        self.assertEquals(oauth_client_patch.call_count, 1)

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.oauth.Client',
                return_value=mocked_oauth_client())
    def test_it_works_with_cache_deactivated(self, oauth_client_patch,
                                             core_client_patch):
        auth = FxABearerTokenAuth(
            email="test@restmail.com",
            password="this is not a password",
            client_id="53210789456",
            account_server_url="https://accounts.com/auth/v1",
            oauth_server_url="https://oauth.com/oauth/v1", cache=False)
        assert not auth.cache
        r = auth(Request())
        self.assertIn('Authorization', r.headers)


class GetCacheKeyTest(unittest.TestCase):
    def test_get_cache_key_return_twice_the_same_key(self):
        args = ['1', '2', 3]
        self.assertEqual(get_cache_key(*args), get_cache_key(*args))

    def test_get_cache_key_can_handle_list(self):
        args = ['1', '2', [3, 'foobar']]
        get_cache_key(*args)

    def test_get_cache_key_can_handle_None(self):
        args = ['1', None, [None, 'foobar']]
        self.assertEqual(get_cache_key(*args), get_cache_key(*args))

    def test_get_cache_key_can_handle_None_as_a_value(self):
        args1 = ['1', None, 2]
        args2 = ['1', 2]
        self.assertNotEqual(get_cache_key(*args1), get_cache_key(*args2))

    def test_get_cache_key_can_handle_value_as_string(self):
        args1 = ['1', '2']
        args2 = ['1', 2]
        self.assertEqual(get_cache_key(*args1), get_cache_key(*args2))
