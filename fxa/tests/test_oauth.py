# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json

import responses

import fxa.errors
from fxa.oauth import Client, scope_matches

from fxa.tests.utils import unittest


TEST_SERVER_URL = "https://server/v1"


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

        self.token = self.client.trade_code('1234')
        self.response = responses.calls[0]

    def test_reaches_server_on_token_url(self):
        self.assertEqual(self.response.request.url,
                         'https://server/v1/token')

    def test_posts_code_to_server(self):
        body = json.loads(self.response.request.body)
        expected = {
            "client_secret": "cake",
            "code": "1234",
            "client_id": "abc"
        }
        self.assertEqual(body, expected)

    def test_returns_access_token_given_by_server(self):
        self.assertEqual(self.token, "yeah")

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
        token = self.client.trade_code('1234', 'abc', 'cake')
        self.assertEqual(token, "tokay")
        # As keyword arguments.
        token = self.client.trade_code(
            code='1234',
            client_id='abc',
            client_secret='cake'
        )
        self.assertEqual(token, "tokay")


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

        self.verification = self.client.verify_token(token='abc')
        self.response = responses.calls[0]

    def test_reaches_server_on_verify_url(self):
        self.assertEqual(self.response.request.url,
                         'https://server/v1/verify')

    def test_posts_token_to_server(self):
        body = json.loads(self.response.request.body)
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
        self.assertRaises(fxa.errors.ScopeMismatchError,
                          self.client.verify_token,
                          token='1234',
                          scope='readinglist')


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
