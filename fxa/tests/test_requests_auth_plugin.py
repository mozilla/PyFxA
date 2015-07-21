from fxa.requests import FxABrowserIdAuth
import mock
from fxa.tests.utils import unittest


class Request(object):
    method = 'GET'
    body = ''
    url = 'http://www.example.com'
    headers = {'Content-Type': 'application/json'}


def mocked_client():
    client = mock.MagicMock()
    session = mock.MagicMock()
    session.get_identity_assertion.return_value = 'abcd'
    session.fetch_keys.return_value = ('keyA'.encode('utf-8'),
                                       'keyB'.encode('utf-8'))
    client.login.return_value = session
    return client


class TestFxABrowserIdAuth(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestFxABrowserIdAuth, self).__init__(*args, **kwargs)
        self.auth = FxABrowserIdAuth(email="test@restmail.com",
                                     password="this is not a password",
                                     server_url="http://localhost:5000")

    @mock.patch('fxa.requests.Client', return_value=mocked_client())
    def test_audience_is_parsed(self, client_patch):
        self.auth(Request())
        self.assertEquals(self.auth.audience, "http://www.example.com/")

    @mock.patch('fxa.requests.Client', return_value=mocked_client())
    def test_server_url_is_passed_to_client(self, client_patch):
        self.auth(Request())
        client_patch.assert_called_with(server_url="http://localhost:5000")

    @mock.patch('fxa.requests.Client', return_value=mocked_client())
    def test_header_are_set_to_request(self, client_patch):
        r = self.auth(Request())
        self.assertIn('Authorization', r.headers)
        self.assertIn('X-Client-State', r.headers)
