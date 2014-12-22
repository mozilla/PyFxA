# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import json

import responses

import fxa.errors
from fxa.oauth import Client


TEST_SERVER_URL = "https://server"


class TestClientTradeCode(unittest.TestCase):

    server_url = TEST_SERVER_URL

    @responses.activate
    def setUp(self):
        self.client = Client(self.server_url)

        body = '{"access_token": "yeah"}'
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body=body,
                      content_type='application/json',
                      adding_headers={'timestamp': '0'})

        self.token = self.client.trade_code(client_id='abc',
                                            client_secret='cake',
                                            code='1234')
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
        self.assertDictEqual(body, expected)

    def test_returns_access_token_given_by_server(self):
        self.assertEqual(self.token, "yeah")

    @responses.activate
    def test_raises_error_if_access_token_not_returned(self):
        responses.add(responses.POST,
                      'https://server/v1/token',
                      body='{"missing": "token"}',
                      content_type='application/json')
        with self.assertRaises(fxa.errors.OutOfProtocolError):
            self.client.trade_code(client_id='abc',
                                   client_secret='cake',
                                   code='1234')


class TestAuthClientVerifyCode(unittest.TestCase):

    server_url = TEST_SERVER_URL

    @responses.activate
    def setUp(self):
        self.client = Client(self.server_url)

        body = '{"user": "alice", "scope": ["profile"], "client_id": "abc"}'
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body=body,
                      content_type='application/json',
                      adding_headers={'timestamp': '0'})

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
        self.assertDictEqual(body, expected)

    def test_returns_response_given_by_server(self):
        expected = {
            "user": "alice",
            "scope": ["profile"],
            "client_id": "abc"
        }
        self.assertDictEqual(self.verification, expected)

    @responses.activate
    def test_raises_error_if_some_attributes_are_not_returned(self):
        responses.add(responses.POST,
                      'https://server/v1/verify',
                      body='{"missing": "attributes"}',
                      content_type='application/json')
        with self.assertRaises(fxa.errors.OutOfProtocolError):
            self.client.verify_token(token='1234')
