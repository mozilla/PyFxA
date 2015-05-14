# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import responses

import fxa.errors
from fxa.profile import Client

from fxa.tests.utils import unittest


TEST_SERVER_URL = "https://profile.server/v1"


class TestProfileClientServerUrl(unittest.TestCase):

    def test_trailing_slash_without_prefix_added_prefix(self):
        client = Client("https://profile.server/")
        self.assertEqual(client.server_url, TEST_SERVER_URL)

    def test_without_prefix_added_prefix(self):
        client = Client("https://profile.server")
        self.assertEqual(client.server_url, TEST_SERVER_URL)

    def test_trailing_slash_with_prefix(self):
        client = Client("https://profile.server/v1/")
        self.assertEqual(client.server_url, TEST_SERVER_URL)

    def test_with_prefix(self):
        client = Client("https://profile.server/v1")
        self.assertEqual(client.server_url, TEST_SERVER_URL)


class TestProfileClientOperations(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client(self.server_url)
        self.token = "mock-bearer-token"

    def _mock_response(self, path, body=None, **body_fields):
        if body is None:
            body = json.dumps(body_fields)
        responses.add(
            responses.GET,
            "https://profile.server/v1" + path,
            body=body,
            content_type="application/json"
        )

    def assertRequestWasAuthorized(self, token):
        authz = responses.calls[0].request.headers["Authorization"]
        self.assertEqual(authz, "Bearer " + token)

    @responses.activate
    def test_get_profile(self):
        self._mock_response(
            "/profile",
            uid="ABCDEF",
            email="test@example.com",
            avatar=None
        )
        resp = self.client.get_profile(self.token)
        self.assertRequestWasAuthorized(self.token)
        self.assertEqual(resp, {
            "uid": "ABCDEF",
            "email": "test@example.com",
            "avatar": None,
        })

    @responses.activate
    def test_get_profile_returns_none_for_missing_attributes(self):
        self._mock_response("/profile", uid="ABCDEF")
        profile = self.client.get_profile(self.token)
        self.assertEqual(profile["uid"], "ABCDEF")
        self.assertEqual(profile["email"], None)

    @responses.activate
    def test_get_email(self):
        self._mock_response("/email", email="test@example.com")
        email = self.client.get_email(self.token)
        self.assertRequestWasAuthorized(self.token)
        self.assertEqual(email, "test@example.com")

    @responses.activate
    def test_get_email_raises_error_on_missing_attributes(self):
        self._mock_response("/email", uid="ABCDEF")
        with self.assertRaises(fxa.errors.OutOfProtocolError):
            self.client.get_email(self.token)

    @responses.activate
    def test_get_uid(self):
        self._mock_response("/uid", uid="123456")
        uid = self.client.get_uid(self.token)
        self.assertRequestWasAuthorized(self.token)
        self.assertEqual(uid, "123456")

    @responses.activate
    def test_get_uid_raises_error_on_missing_attributes(self):
        self._mock_response("/uid")
        with self.assertRaises(fxa.errors.OutOfProtocolError):
            self.client.get_uid(self.token)

    @responses.activate
    def test_get_avatar_url(self):
        self._mock_response("/avatar", url="https://example.com/blah")
        url = self.client.get_avatar_url(self.token)
        self.assertRequestWasAuthorized(self.token)
        self.assertEqual(url, "https://example.com/blah")

    @responses.activate
    def test_get_avatar_url_raises_error_on_missing_attributes(self):
        self._mock_response("/avatar", id="corrupted-avatar")
        with self.assertRaises(fxa.errors.OutOfProtocolError):
            self.client.get_avatar_url(self.token)
