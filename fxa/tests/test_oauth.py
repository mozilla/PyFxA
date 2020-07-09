# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import json
import jwt
import responses
import six
try:
    from unittest import mock
except ImportError:
    import mock

import fxa.errors
from fxa.cache import MemoryCache
from fxa.oauth import Client, scope_matches
from fxa._utils import _decoded
from fxa.tests.utils import unittest

from six.moves.urllib.parse import urlparse, parse_qs


TEST_SERVER_URL = "https://server/v1"


def add_jwks_response():
    responses.add(responses.GET,
                  'https://server/v1/jwks',
                  body=open(os.path.join(os.path.dirname(__file__), "jwks.json")).read(),
                  content_type='application/json')


class TestClientServerUrl(unittest.TestCase):
    def test_trailing_slash_without_prefix_added_prefix(self):
        client = Client('abc', 'cake', "https://server/")
        self.assertEqual(client.apiclient.server_url, TEST_SERVER_URL)

    def test_without_prefix_added_prefix(self):
        client = Client('abc', 'cake', "https://server")
        self.assertEqual(client.apiclient.server_url, TEST_SERVER_URL)

    def test_trailing_slash_with_prefix(self):
        client = Client('abc', 'cake', "https://server/v1/")
        self.assertEqual(client.apiclient.server_url, TEST_SERVER_URL)

    def test_with_prefix(self):
        client = Client('abc', 'cake', "https://server/v1")
        self.assertEqual(client.apiclient.server_url, TEST_SERVER_URL)


class TestClientTradeCode(unittest.TestCase):

    server_url = TEST_SERVER_URL

    @responses.activate
    def setUp(self):
        self.client = Client('abc', 'cake', self.server_url)

        body = '{"access_token": "yeah"}'
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body=body,
                      content_type='application/json')

        self.tokens = self.client.trade_code('1234')
        self.response = responses.calls[0]

    def _get_request_body(self):
        return json.loads(_decoded(responses.calls[0].request.body))

    def test_reaches_server_on_token_url(self):
        self.assertEqual(self.response.request.url,
                         'https://server/v1/token')

    def test_posts_code_to_server(self):
        body = json.loads(_decoded(self.response.request.body))
        expected = {
            "client_secret": "cake",
            "code": "1234",
            "client_id": "abc"
        }
        self.assertEqual(body, expected)

    def test_returns_access_token_given_by_server(self):
        self.assertEqual(self.tokens["access_token"], "yeah")

    @responses.activate
    def test_raises_error_if_access_token_not_returned(self):
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body='{"missing": "token"}',
                      content_type='application/json')
        self.assertRaises(fxa.errors.OutOfProtocolError,
                          self.client.trade_code,
                          client_id='abc',
                          client_secret='cake',
                          code='1234')

    @responses.activate
    def test_trade_token_can_take_client_credentials_as_arguments(self):
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body='{"access_token": "tokay"}',
                      content_type='application/json')
        # As positional arguments.
        tokens = self.client.trade_code('1234', 'abc', 'cake2')
        self.assertEqual(tokens, {"access_token": "tokay"})
        self.assertEqual(self._get_request_body(), {
          'client_id': 'abc',
          'client_secret': 'cake2',
          'code': '1234',
        })
        # As keyword arguments.
        tokens = self.client.trade_code(
            code='1234',
            client_id='abc',
            client_secret='cake2'
        )
        self.assertEqual(tokens, {"access_token": "tokay"})
        self.assertEqual(self._get_request_body(), {
          'client_id': 'abc',
          'client_secret': 'cake2',
          'code': '1234',
        })

    @responses.activate
    def test_trade_token_can_take_pkce_verifier_as_argument(self):
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body='{"access_token": "tokay"}',
                      content_type='application/json')
        tokens = self.client.trade_code(
            code='1234',
            code_verifier='verifyme',
        )
        self.assertEqual(tokens, {"access_token": "tokay"})
        self.assertEqual(self._get_request_body(), {
          'client_id': 'abc',
          'client_secret': 'cake',
          'code': '1234',
          'code_verifier': 'verifyme',
        })

    @responses.activate
    def test_trade_token_can_take_ttl(self):
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body='{"access_token": "tokay"}',
                      content_type='application/json')
        tokens = self.client.trade_code(
            code='1234',
            ttl=120,
        )
        self.assertEqual(tokens, {"access_token": "tokay"})
        self.assertEqual(self._get_request_body(), {
          'client_id': 'abc',
          'client_secret': 'cake',
          'code': '1234',
          'ttl': 120
        })


class TestAuthClientVerifyCode(unittest.TestCase):

    server_url = TEST_SERVER_URL

    @responses.activate
    def setUp(self):
        self.client = Client(server_url=self.server_url)

        body = '{"user": "alice", "scope": ["profile"], "client_id": "abc"}'
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body=body,
                      content_type='application/json')
        add_jwks_response()
        self.verification = self.client.verify_token(token='abc')
        self.response = responses.calls[1]

    def test_reaches_server_on_verify_url(self):
        self.assertEqual(self.response.request.url,
                         'https://server/v1/verify')

    def test_posts_token_to_server(self):
        body = json.loads(_decoded(self.response.request.body))
        expected = {
            "token": "abc",
        }
        self.assertEqual(body, expected)

    def test_returns_response_given_by_server(self):
        expected = {
            "user": "alice",
            "scope": ["profile"],
            "client_id": "abc"
        }
        self.assertEqual(self.verification, expected)

    @responses.activate
    def test_raises_error_if_some_attributes_are_not_returned(self):
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body='{"missing": "attributes"}',
                      content_type='application/json')
        add_jwks_response()
        self.assertRaises(fxa.errors.OutOfProtocolError,
                          self.client.verify_token,
                          token='1234')

    @responses.activate
    def test_raises_error_if_scopes_do_not_match(self):
        body = '{"user": "alice", "scope": ["files"], "client_id": "abc"}'
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body=body,
                      content_type='application/json')
        add_jwks_response()
        self.assertRaises(fxa.errors.ScopeMismatchError,
                          self.client.verify_token,
                          token='1234',
                          scope='readinglist')


class TestOAuthClientRedirectURL(unittest.TestCase):

    server_url = TEST_SERVER_URL

    @responses.activate
    def setUp(self):
        self.client = Client("abcdef", server_url=self.server_url)

    def test_redirect_url_with_default_arguments(self):
        redirect_url = urlparse(self.client.get_redirect_url())
        server_url = urlparse(self.server_url)
        self.assertEqual(redirect_url.hostname, server_url.hostname)
        self.assertEqual(redirect_url.path,
                         server_url.path + "/authorization")
        params = parse_qs(redirect_url.query, keep_blank_values=True)
        self.assertEqual(sorted(params.keys()), ["client_id", "state"])
        self.assertEqual(params["client_id"][0], self.client.client_id)
        self.assertEqual(params["state"][0], "")

    def test_redirect_url_takes_custom_client_id(self):
        redirect_url = urlparse(self.client.get_redirect_url(client_id="XX"))
        params = parse_qs(redirect_url.query, keep_blank_values=True)
        self.assertEqual(sorted(params.keys()), ["client_id", "state"])
        self.assertEqual(params["client_id"][0], "XX")

    def test_redirect_url_takes_custom_url_parameters(self):
        redirect_url = urlparse(self.client.get_redirect_url(
            state="applicationstate",
            redirect_uri="https://my.site/oauth",
            scope="profile profile:email",
            action="signup",
            email="test@example.com",
            code_challenge="challenge",
            code_challenge_method="S1234",
            access_type="offline",
            keys_jwk="MockJWK",
        ))
        server_url = urlparse(self.server_url)
        self.assertEqual(redirect_url.hostname, server_url.hostname)
        params = parse_qs(redirect_url.query, keep_blank_values=True)
        all_params = ["action", "email", "client_id", "redirect_uri",
                      "scope", "state", "access_type", "code_challenge",
                      "code_challenge_method", "keys_jwk"]
        self.assertEqual(sorted(params.keys()), sorted(all_params))
        self.assertEqual(params["client_id"][0], self.client.client_id)
        self.assertEqual(params["state"][0], "applicationstate")
        self.assertEqual(params["redirect_uri"][0], "https://my.site/oauth")
        self.assertEqual(params["scope"][0], "profile profile:email")
        self.assertEqual(params["action"][0], "signup")
        self.assertEqual(params["email"][0], "test@example.com")
        self.assertEqual(params["code_challenge"][0], "challenge")
        self.assertEqual(params["code_challenge_method"][0], "S1234")
        self.assertEqual(params["access_type"][0], "offline")
        self.assertEqual(params["keys_jwk"][0], "MockJWK")


class TestAuthClientAuthorizeCode(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        def authorization_callback(request):
            data = json.loads(_decoded(request.body))
            headers = {
                'Content-Type': 'application/json'
            }
            body = {
                'redirect': 'https://relier/page?code=qed&state={}'.format(data["state"])
            }
            return (200, headers, json.dumps(body))

        self.client = Client("abc", "xyz", server_url=self.server_url)
        responses.add_callback(responses.POST,
                               'https://server/v1/authorization',
                               callback=authorization_callback,
                               content_type='application/json')

    @responses.activate
    def test_authorize_code_with_default_arguments(self):
        assertion = "A_FAKE_ASSERTION"
        code = self.client.authorize_code(assertion)
        self.assertEqual(code, "qed")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
        })

    @responses.activate
    def test_authorize_code_with_explicit_scope(self):
        assertion = "A_FAKE_ASSERTION"
        code = self.client.authorize_code(assertion, scope="profile:email")
        self.assertEqual(code, "qed")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
            "scope": "profile:email",
        })

    @responses.activate
    def test_authorize_code_with_explicit_client_id(self):
        assertion = "A_FAKE_ASSERTION"
        code = self.client.authorize_code(assertion, client_id="cba")
        self.assertEqual(code, "qed")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": "cba",
            "state": AnyStringValue(),
        })

    @responses.activate
    def test_authorize_code_with_pkce_challenge(self):
        assertion = "A_FAKE_ASSERTION"
        challenge, verifier = self.client.generate_pkce_challenge()
        self.assertEqual(sorted(challenge),
                         ["code_challenge", "code_challenge_method"])
        self.assertEqual(sorted(verifier),
                         ["code_verifier"])
        code = self.client.authorize_code(assertion, **challenge)
        self.assertEqual(code, "qed")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
            "code_challenge": challenge["code_challenge"],
            "code_challenge_method": challenge["code_challenge_method"],
        })

    @responses.activate
    def test_authorize_code_with_session_object(self):
        session = mock.Mock()
        session.get_identity_assertion.return_value = "IDENTITY"
        code = self.client.authorize_code(session)
        session.get_identity_assertion.assert_called_once_with(
            audience=TEST_SERVER_URL,
            service=self.client.client_id
        )
        self.assertEqual(code, "qed")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": "IDENTITY",
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
        })


class TestAuthClientAuthorizeToken(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client("abc", "xyz", server_url=self.server_url)
        responses.add(responses.POST,
                      'https://server/v1/authorization',
                      body='{"access_token": "izatoken"}',
                      content_type='application/json')
        add_jwks_response()

    @responses.activate
    def test_authorize_token_with_default_arguments(self):
        assertion = "A_FAKE_ASSERTION"
        token = self.client.authorize_token(assertion)
        self.assertEqual(token, "izatoken")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
            "response_type": "token",
        })

    @responses.activate
    def test_authorize_token_with_explicit_scope(self):
        assertion = "A_FAKE_ASSERTION"
        token = self.client.authorize_token(assertion, scope="storage")
        self.assertEqual(token, "izatoken")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
            "response_type": "token",
            "scope": "storage",
        })

    @responses.activate
    def test_authorize_token_with_explicit_client_id(self):
        assertion = "A_FAKE_ASSERTION"
        token = self.client.authorize_token(assertion, client_id="cba")
        self.assertEqual(token, "izatoken")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": assertion,
            "client_id": "cba",
            "state": AnyStringValue(),
            "response_type": "token",
        })

    @responses.activate
    def test_authorize_token_with_session_object(self):
        session = mock.Mock()
        session.get_identity_assertion.return_value = "IDENTITY"
        token = self.client.authorize_token(session)
        session.get_identity_assertion.assert_called_once_with(
            audience=TEST_SERVER_URL,
            service=self.client.client_id
        )
        self.assertEqual(token, "izatoken")
        req_body = json.loads(_decoded(responses.calls[0].request.body))
        self.assertEqual(req_body, {
            "assertion": "IDENTITY",
            "client_id": self.client.client_id,
            "state": AnyStringValue(),
            "response_type": "token",
        })


class TestScopeMatch(unittest.TestCase):
    def test_always_matches_if_required_is_empty(self):
        self.assertTrue(scope_matches(['abc'], []))

    def test_do_not_match_if_invalid_scope_provided(self):
        self.assertFalse(scope_matches(['abc'], ''))
        with self.assertRaises(Exception):
            scope_matches(['abc'], None)

    def test_do_not_match_if_root_scopes_are_different(self):
        self.assertFalse(scope_matches(['abc'], 'def'))
        self.assertFalse(scope_matches(['abc'], ['def']))

    def test_matches_if_root_scopes_are_the_same(self):
        self.assertTrue(scope_matches(['abc', 'def'], 'abc'))
        self.assertTrue(scope_matches(['abc', 'def'], ['abc']))

    def test_matches_if_one_of_required_is_not_provided(self):
        self.assertFalse(scope_matches(['abc'], ['abc', 'def']))

    def test_matches_if_required_is_a_subscope(self):
        self.assertTrue(scope_matches(['abc'], 'abc:xyz'))
        self.assertTrue(scope_matches(['abc'], ['abc:xyz']))
        self.assertTrue(scope_matches(['abc', 'def'], ['abc:xyz', 'def']))
        self.assertTrue(scope_matches(['abc', 'def'], ['abc:xyz', 'def:123']))

    def test_do_not_match_if_subscopes_do_not_match(self):
        self.assertFalse(scope_matches(['abc:xyz'], 'abc:123'))
        self.assertFalse(scope_matches(['abc:xyz'], ['abc:xyz', 'abc:123']))

    def test_do_not_match_if_provided_is_a_subscope(self):
        self.assertFalse(scope_matches(['abc:xyz'], 'abc'))
        self.assertFalse(scope_matches(['abc:xyz'], ['abc']))
        self.assertFalse(scope_matches(['abc:xyz', 'def'], ['abc', 'def']))

    def test_published_test_vectors_for_valid_matches(self):
        VALID_MATCHES = [
            ['profile:write', 'profile'],
            ['profile', 'profile:email'],
            ['profile:write', 'profile:email'],
            ['profile:write', 'profile:email:write'],
            ['profile:email:write', 'profile:email'],
            ['profile profile:email:write', 'profile:email'],
            ['profile profile:email:write', 'profile:display_name'],
            ['profile https://identity.mozilla.com/apps/oldsync', 'profile'],
            ['foo bar:baz', 'foo:dee'],
            ['foo bar:baz', 'bar:baz'],
            ['foo bar:baz', 'foo:mah:pa bar:baz:quux'],
            ['profile https://identity.mozilla.com/apps/oldsync',
                'https://identity.mozilla.com/apps/oldsync'],
            ['https://identity.mozilla.com/apps/oldsync',
                'https://identity.mozilla.com/apps/oldsync#read'],
            ['https://identity.mozilla.com/apps/oldsync',
                'https://identity.mozilla.com/apps/oldsync/bookmarks'],
            ['https://identity.mozilla.com/apps/oldsync',
                'https://identity.mozilla.com/apps/oldsync/bookmarks#read'],
            ['https://identity.mozilla.com/apps/oldsync#read',
                'https://identity.mozilla.com/apps/oldsync/bookmarks#read'],
            ['https://identity.mozilla.com/apps/oldsync#read profile',
                'https://identity.mozilla.com/apps/oldsync/bookmarks#read']
        ]
        for (provided, required) in VALID_MATCHES:
            self.assertTrue(scope_matches(provided.split(), required.split()),
                            '"{}" should match "{}"'.format(provided, required))

    def test_published_test_vectors_for_invalid_matches(self):
        INVALID_MATCHES = [
            ['profile:email:write', 'profile'],
            ['profile:email:write', 'profile:write'],
            ['profile:email', 'profile:display_name'],
            ['profilebogey', 'profile'],
            ['foo bar:baz', 'bar'],
            ['profile:write', 'https://identity.mozilla.com/apps/oldsync'],
            ['profile profile:email:write', 'profile:write'],
            ['https', 'https://identity.mozilla.com/apps/oldsync'],
            ['https://identity.mozilla.com/apps/oldsync', 'profile'],
            ['https://identity.mozilla.com/apps/oldsync#read',
                'https://identity.mozila.com/apps/oldsync/bookmarks'],
            ['https://identity.mozilla.com/apps/oldsync#write',
                'https://identity.mozila.com/apps/oldsync/bookmarks#read'],
            ['https://identity.mozilla.com/apps/oldsync/bookmarks',
                'https://identity.mozila.com/apps/oldsync'],
            ['https://identity.mozilla.com/apps/oldsync/bookmarks',
                'https://identity.mozila.com/apps/oldsync/passwords'],
            ['https://identity.mozilla.com/apps/oldsyncer',
                'https://identity.mozila.com/apps/oldsync'],
            ['https://identity.mozilla.com/apps/oldsync',
                'https://identity.mozila.com/apps/oldsyncer'],
            ['https://identity.mozilla.org/apps/oldsync',
                'https://identity.mozila.com/apps/oldsync']
        ]
        for (provided, required) in INVALID_MATCHES:
            self.assertFalse(scope_matches(provided.split(), required.split()),
                             '"{}" should not match "{}"'.format(provided, required))


class TestCachedClient(unittest.TestCase):
    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client(server_url=self.server_url)
        self.body = ('{"user": "alice", "scope": ["profile"],'
                     '"client_id": "abc"}')
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body=self.body,
                      content_type='application/json')
        add_jwks_response()

    def test_has_default_cache(self):
        self.assertIsNotNone(self.client.cache)
        self.assertEqual(self.client.cache.ttl, 300)

    def test_can_change_default_cache(self):
        cache = MemoryCache(0.01)
        self.client = Client(cache=cache)
        self.assertEqual(self.client.cache, cache)
        self.assertEqual(self.client.cache.ttl, 0.01)

    def test_can_deactivate_cache(self):
        self.client = Client(cache=None)
        self.assertIsNone(self.client.cache)

    @responses.activate
    def test_client_verify_code_is_cached(self):
        with mock.patch.object(self.client.cache, 'set') as mocked_set:
            with mock.patch.object(self.client.cache, 'get',
                                   return_value=None):
                # First call
                verification = self.client.verify_token(token='abc')
                self.assertTrue(mocked_set.called)
                self.assertDictEqual(verification, json.loads(self.body))

    @responses.activate
    def test_client_verify_code_cached_value_is_used(self):
        with mock.patch.object(self.client.cache, 'set') as mocked_set:
            with mock.patch.object(self.client.cache, 'get',
                                   return_value=self.body):
                # Second call
                verification = self.client.verify_token(token='abc')
                self.assertFalse(mocked_set.called)
                self.assertDictEqual(verification, json.loads(self.body))

    @responses.activate
    def test_client_verify_code_cached_value_is_not_used_if_no_cache(self):
        self.client = Client(cache=None, server_url=self.server_url)
        # First call
        verification = self.client.verify_token(token='abc')
        self.assertDictEqual(verification, json.loads(self.body))

        # Second call
        verification = self.client.verify_token(token='abc')
        self.assertDictEqual(verification, json.loads(self.body))


class TestGeventPatch(unittest.TestCase):

    @unittest.skipUnless(six.PY2, "gevent works only with Python 2")
    def test_monkey_patch_for_gevent(self):
        import fxa
        import fxa._utils
        import grequests
        old_requests = fxa._utils.requests

        fxa.monkey_patch_for_gevent()
        self.assertNotEqual(fxa._utils.requests, old_requests)
        self.assertEqual(fxa._utils.requests, grequests)

        fxa._utils.requests = old_requests


class TestJwtToken(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def callback(self, request):
        if self.verify_will_succeed:
            return (200, {}, self.body)
        return (500, {}, '{}')

    def _make_jwt(self, payload, key, alg="RS256", header={"typ": "at+jwt"}):
        header = header.copy()  # So we don't accidentally mutate argument in-place
        return six.ensure_text(jwt.encode(payload, key, alg, header))

    def setUp(self):
        self.client = Client(server_url=self.server_url)
        self.body = ('{"user": "alice", "scope": ["profile"],'
                     '"client_id": "abc"}')
        responses.add_callback(responses.POST,
                               'https://server/v1/verify',
                               callback=self.callback,
                               content_type='application/json')
        add_jwks_response()
        self.verify_will_succeed = True

    def get_file_contents(self, filename):
        return jwt.algorithms.RSAAlgorithm.from_jwk(open(
            os.path.join(
                os.path.dirname(__file__),
                filename
            )
        ).read())

    @responses.activate
    def test_good_jwt_token(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({
            "sub": "asdf",
            "scope": "qwer",
            "client_id": "foo"
        }, private_key)
        self.client.verify_token(token)
        for c in responses.calls:
            if c.request.url == 'https://server/v1/verify':
                raise Exception("testing with a good token should not have \
                                 resulted in a call to /verify, but it did.")

    @responses.activate
    def test_good_jwt_token_with_long_form_typ_header(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({
            "sub": "asdf",
            "scope": "qwer",
            "client_id": "foo"
        }, private_key, header={
            "typ": "application/at+JWT",
        })
        self.client.verify_token(token)
        for c in responses.calls:
            if c.request.url == 'https://server/v1/verify':
                raise Exception("testing with a good token should not have \
                                 resulted in a call to /verify, but it did.")

    @responses.activate
    def test_good_jwt_token_with_correct_scope(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({
            "sub": "asdf",
            "scope": "qwer tee",
            "client_id": "foo"
        }, private_key)
        self.client.verify_token(token, scope="tee")

    @responses.activate
    def test_good_jwt_token_with_incorrect_scope(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({
            "sub": "asdf",
            "scope": "qwer",
            "client_id": "foo"
        }, private_key)
        with self.assertRaises(fxa.errors.TrustError):
            self.client.verify_token(token, scope="tee")

    @responses.activate
    def test_wrong_key_jwt_token(self):
        self.verify_will_succeed = False
        bad_key = self.get_file_contents("bad-key.json")
        token = self._make_jwt({}, bad_key)
        with self.assertRaises(fxa.errors.TrustError):
            self.client.verify_token(token)
        for c in responses.calls:
            if c.request.url == 'https://server/v1/verify':
                raise Exception("testing with a well-formed token with invalid signature \
                                 should not have resulted in a call to /verify, but it did.")

    @responses.activate
    def test_expired_jwt_token(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({"qwer": "asdf", "exp": 0}, private_key)
        with self.assertRaises(fxa.errors.TrustError):
            self.client.verify_token(token)

    @responses.activate
    def test_jwt_token_with_wrong_typ(self):
        private_key = self.get_file_contents("private-key.json")
        token = self._make_jwt({"qwer": "asdf", "exp": 0}, private_key, header={
          "typ": "rt+jwt"
        })
        with self.assertRaises(fxa.errors.TrustError):
            self.client.verify_token(token)

    @responses.activate
    def test_garbage_jwt_token(self):
        self.verify_will_succeed = False
        with self.assertRaises(fxa.errors.ServerError):
            self.client.verify_token("garbage")
        for c in responses.calls:
            if c.request.url == 'https://server/v1/verify':
                break
        else:
            raise Exception("testing with a garbage token should have \
                             called /verify, but it did not.")


class AnyStringValue:

    def __eq__(self, other):
        return isinstance(other, six.string_types)

    def __repr__(self):
        return 'any string'
