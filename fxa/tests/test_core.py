# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

import fxa.errors
from fxa.core import Client
from fxa.crypto import quick_stretch_password

from fxa.tests.utils import (
    TestEmailAccount,
    DUMMY_PASSWORD,
    DUMMY_STRETCHED_PASSWORD,
)


# XXX TODO: this currently talks to a live server by default.
# It's nice to have such an option, but we shouldn't hit the network
# for every test run.  Instead let's build a mock server and use that.
TEST_SERVER_URL = "https://stable.dev.lcip.org/auth"


class TestCoreClient(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client(self.server_url)
        self._accounts_to_delete = []

    def tearDown(self):
        for acct in self._accounts_to_delete:
            acct.clear()
            try:
                stretchpwd = acct.stretchpwd
            except AttributeError:
                try:
                    password = acct.password
                    stretchpwd = quick_stretch_password(acct.email, password)
                except AttributeError:
                    stretchpwd = DUMMY_STRETCHED_PASSWORD
            self.client.destroy_account(acct.email, stretchpwd=stretchpwd)

    def test_account_creation(self):
        acct = TestEmailAccount()
        acct.password = DUMMY_PASSWORD
        session = self.client.create_account(acct.email, DUMMY_PASSWORD)
        self._accounts_to_delete.append(acct)
        self.assertEqual(session.email, acct.email)
        self.assertFalse(session.verified)
        self.assertEqual(session.keys, None)
        self.assertEqual(session._key_fetch_token, None)
        with self.assertRaises(Exception):
            session.fetch_keys()

    def test_account_creation_with_key_fetch(self):
        acct = TestEmailAccount()
        session = self.client.create_account(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
            keys=True,
        )
        self._accounts_to_delete.append(acct)
        self.assertEqual(session.email, acct.email)
        self.assertFalse(session.verified)
        self.assertEqual(session.keys, None)
        self.assertNotEqual(session._key_fetch_token, None)


class TestCoreClientSession(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client(self.server_url)
        # Create a fresh testing account.
        self.acct = TestEmailAccount()
        self.stretchpwd = DUMMY_STRETCHED_PASSWORD
        self.session = self.client.create_account(
            email=self.acct.email,
            stretchpwd=self.stretchpwd,
            keys=True,
        )
        # Verify the account so that we can actually use the session.
        m = self.acct.wait_for_email(lambda m: "x-verify-code" in m["headers"])
        if not m:
            raise RuntimeError("Verification email was not received")
        self.session.verify_email_code(m["headers"]["x-verify-code"])
        # Fetch the keys.
        self.session.fetch_keys()
        self.assertEqual(len(self.session.keys), 2)
        self.assertEqual(len(self.session.keys[0]), 32)
        self.assertEqual(len(self.session.keys[1]), 32)

    def tearDown(self):
        # Clean up the session and account.
        # This might fail if the test already cleaned it up.
        try:
            self.session.destroy_session()
        except fxa.errors.ClientError:
            pass
        try:
            self.client.destroy_account(
                email=self.acct.email,
                stretchpwd=self.stretchpwd,
            )
        except fxa.errors.ClientError:
            pass
        self.acct.clear()

    def test_session_status(self):
        self.session.check_session_status()
        self.session.destroy_session()
        with self.assertRaises(fxa.errors.ClientError):
            self.session.check_session_status()

    def test_email_status(self):
        status = self.session.get_email_status()
        self.assertTrue(status["verified"])
