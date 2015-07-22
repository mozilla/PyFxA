from fxa.plugins.requests import FxABrowserIDAuth
import mock
from fxa.tests.utils import unittest


class Request(object):
    def __init__(self):
        self.method = 'GET'
        self.body = ''
        self.url = 'http://www.example.com'
        self.headers = {'Content-Type': 'application/json'}


def mocked_client():
    client = mock.MagicMock()
    session = mock.MagicMock()
    session.get_identity_assertion.return_value = 'abcd'
    session.fetch_keys.return_value = ('keyA'.encode('utf-8'),
                                       'keyB'.encode('utf-8'))
    client.login.return_value = session
    return client


class TestFxABrowserIDAuth(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestFxABrowserIDAuth, self).__init__(*args, **kwargs)
        self.auth = FxABrowserIDAuth(email="test@restmail.com",
                                     password="this is not a password",
                                     with_client_state=True,
                                     server_url="http://localhost:5000")

    @mock.patch('fxa.plugins.requests.Client', return_value=mocked_client())
    def test_audience_is_parsed(self, client_patch):
        self.auth(Request())
        self.assertEquals(self.auth.audience, "http://www.example.com/")

    @mock.patch('fxa.plugins.requests.Client', return_value=mocked_client())
    def test_server_url_is_passed_to_client(self, client_patch):
        self.auth(Request())
        client_patch.assert_called_with(server_url="http://localhost:5000")

    @mock.patch('fxa.plugins.requests.Client', return_value=mocked_client())
    def test_header_are_set_to_request(self, client_patch):
        r = self.auth(Request())
        self.assertIn('Authorization', r.headers)
        self.assertTrue(r.headers['Authorization'].startswith("BrowserID"),
                        "Authorization headers does not start with BrowserID")
        self.assertIn('X-Client-State', r.headers)

    @mock.patch('fxa.plugins.requests.Client', return_value=mocked_client())
    def test_client_state_not_set_by_default(self, client_patch):
        auth = FxABrowserIDAuth(email="test@restmail.com",
                                password="this is not a password",
                                server_url="http://localhost:5000")
        r = auth(Request())
        self.assertNotIn('X-Client-State', r.headers)
