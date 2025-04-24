# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import time

from urllib.parse import urlparse

import pyotp
import pytest
from parameterized import parameterized_class

import fxa.errors
from fxa.core import Client, StretchedPassword

from fxa.tests.utils import (
    unittest,
    mutate_one_byte,
    TestEmailAccount,
    DUMMY_PASSWORD,
)


# XXX TODO: this currently talks to a live server by default.
# It's nice to have such an option, but we shouldn't hit the network
# for every test run.  Instead let's build a mock server and use that.
TEST_SERVER_URL = "https://api-accounts.stage.mozaws.net/v1/"


@parameterized_class([
   {"key_stretch_version": 1},
   {"key_stretch_version": 2},
])
class TestCoreClient(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client_v1 = Client(self.server_url)
        self.client_v2 = Client(self.server_url, key_stretch_version=2)
        if self.key_stretch_version == 2:
            self.client = self.client_v2
        else:
            self.client = self.client_v1
        self._accounts_to_delete = []

    def add_account_to_delete(self, acct, session):
        acct.stretchpwd = session.stretchpwd
        self._accounts_to_delete.append(acct)

    def tearDown(self):
        for acct in self._accounts_to_delete:
            acct.clear()
            if isinstance(acct.stretchpwd, StretchedPassword):
                self.client_v2.destroy_account(acct.email, stretchpwd=acct.stretchpwd)
            elif isinstance(acct.stretchpwd, bytes):
                self.client_v1.destroy_account(acct.email, stretchpwd=acct.stretchpwd)
            else:
                raise ValueError("Invalid acct.stretchpwd")

    def test_account_creation(self):
        acct = TestEmailAccount()
        session = self.client.create_account(acct.email, DUMMY_PASSWORD)
        self.add_account_to_delete(acct, session)
        version, _ = self.client.get_key_stretch_version(acct.email)

        self.assertIsNotNone(session.stretchpwd)
        self.assertEqual(session.email, acct.email)
        self.assertFalse(session.verified)
        self.assertEqual(session.keys, None)
        self.assertEqual(session._key_fetch_token, None)
        self.assertEqual(version, self.key_stretch_version)
        with self.assertRaises(Exception):
            session.fetch_keys()

    def test_account_creation_with_key_fetch(self):
        acct = TestEmailAccount()
        session = self.client.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
            keys=True,
        )
        self.add_account_to_delete(acct, session)
        version, _ = self.client.get_key_stretch_version(acct.email)

        self.assertIsNotNone(session.stretchpwd)
        self.assertEqual(session.email, acct.email)
        self.assertFalse(session.verified)
        self.assertEqual(session.keys, None)
        self.assertNotEqual(session._key_fetch_token, None)
        self.assertEqual(version, self.key_stretch_version)

    def test_account_login(self):
        acct = TestEmailAccount()
        session1 = self.client.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
        )
        self.add_account_to_delete(acct, session1)

        session2 = self.client.login(
            email=acct.email,
            stretchpwd=session1.stretchpwd,
        )
        self.assertEqual(session1.email, session2.email)
        self.assertNotEqual(session1.token, session2.token)

    def test_get_random_bytes(self):
        b1 = self.client.get_random_bytes()
        b2 = self.client.get_random_bytes()
        self.assertTrue(isinstance(b1, bytes))
        self.assertNotEqual(b1, b2)

    @pytest.mark.skip(reason="Gets rate limited.")
    def test_resend_verify_code(self):
        acct = TestEmailAccount()
        session = self.client.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
        )
        self.add_account_to_delete(acct, session)

        def is_verify_email(m):
            return "x-verify-code" in m["headers"]

        m1 = acct.wait_for_email(is_verify_email)
        code1 = m1["headers"]["x-verify-code"]  # NOQA
        acct.clear()
        session.resend_email_code()
        # XXX TODO: this won't work against a live server because we
        # refuse to send duplicate emails within a short timespan.
        # m2 = acct.wait_for_email(is_verify_email)
        # code2 = m2["headers"]["x-verify-code"]
        # self.assertNotEqual(m1, m2)
        # self.assertEqual(code1, code2)

    def test_forgot_password_flow(self):
        acct = TestEmailAccount()
        session = self.client.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
        )
        self.add_account_to_delete(acct, session)

        # Initiate the password reset flow, and grab the verification code.
        pftok = self.client.send_reset_code(acct.email, service="foobar")
        m = acct.wait_for_email(lambda m: "x-recovery-code" in m["headers"])
        if not m:
            raise RuntimeError("Password reset email was not received")
        acct.clear()
        code = m["headers"]["x-recovery-code"]

        # Try with an invalid code to test error handling.
        tries = pftok.tries_remaining
        self.assertTrue(tries > 1)
        with self.assertRaises(Exception):
            pftok.verify_code(mutate_one_byte(code))
        pftok.get_status()
        self.assertEqual(pftok.tries_remaining, tries - 1)

        # Re-send the code, as if we've lost the email.
        pftok.resend_code()
        m = acct.wait_for_email(lambda m: "x-recovery-code" in m["headers"])
        if not m:
            raise RuntimeError("Password reset email was not received")
        self.assertEqual(m["headers"]["x-recovery-code"], code)

        # Now verify with the actual code, and reset the account.
        artok = pftok.verify_code(code)
        self.client.reset_account(
            email=acct.email,
            token=artok,
            password=DUMMY_PASSWORD
        )

    def test_email_code_verification(self):
        self.client = Client(self.server_url)
        # Create a fresh testing account.
        self.acct = TestEmailAccount()
        session = self.client.create_account(
            email=self.acct.email,
            password=DUMMY_PASSWORD
        )
        self.add_account_to_delete(self.acct, session)

        def wait_for_email(m):
            return "x-uid" in m["headers"] and "x-verify-code" in m["headers"]

        m = self.acct.wait_for_email(wait_for_email)
        if not m:
            raise RuntimeError("Verification email was not received")
        # If everything went well, verify_email_code should return an empty json object
        response = self.client.verify_email_code(m["headers"]["x-uid"],
                                                 m["headers"]["x-verify-code"])
        self.assertEqual(response, {})

    @pytest.mark.skip(reason="Endpoint no longer supported.")
    def test_send_unblock_code(self):
        acct = TestEmailAccount(email="block-{uniq}@{hostname}")
        session = self.client.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD
        )
        self.add_account_to_delete(acct, session)

        # Initiate sending unblock code
        response = self.client.send_unblock_code(acct.email)
        self.assertEqual(response, {})

        m = acct.wait_for_email(lambda m: "x-unblock-code" in m["headers"])
        if not m:
            raise RuntimeError("Unblock code email was not received")

        code = m["headers"]["x-unblock-code"]
        self.assertTrue(len(code) > 0)

        self.client.login(
            email=acct.email,
            password=DUMMY_PASSWORD,
            unblock_code=code
        )

    def test_key_stretch_upgrade(self):
        # Only applicable for V2 key stretch
        if self.key_stretch_version == 1:
            return

        # Create account using key stretch v1 mode
        acct = TestEmailAccount()
        session1 = self.client_v1.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
            keys=True
        )
        self.add_account_to_delete(acct, session1)
        verify_account(acct, self.client_v1)
        version1, _ = self.client_v2.get_key_stretch_version(acct.email)
        keys1 = session1.fetch_keys()

        # Login with using key stretch v2 mode
        session2 = self.client_v2.login(email=acct.email, password=DUMMY_PASSWORD, keys=True)
        version2, _ = self.client_v2.get_key_stretch_version(acct.email)
        keys2 = session2.fetch_keys()

        self.assertEqual(version1, 1)
        self.assertEqual(version2, 2)
        self.assertEqual(keys1[0], keys2[0])
        self.assertEqual(keys1[1], keys2[1])

    def test_legacy_key_stretch_support(self):
        # Only applicable for V2 key stretch
        if self.key_stretch_version == 1:
            return

        # Create account with V2 key stretching enabled
        acct = TestEmailAccount()
        session = self.client_v2.create_account(
            email=acct.email,
            password=DUMMY_PASSWORD,
            keys=True
        )
        self.add_account_to_delete(acct, session)
        verify_account(acct, self.client_v2)
        version_1, _ = self.client_v2.get_key_stretch_version(acct.email)
        keys_1 = session.fetch_keys()

        # Login with key stretch v1 enabled and get keys
        session = self.client_v1.login(email=acct.email, password=DUMMY_PASSWORD, keys=True)
        version_2, _ = self.client_v2.get_key_stretch_version(acct.email)
        keys_2 = session.fetch_keys()

        self.assertEqual(version_1, 2)
        self.assertEqual(version_2, 2)
        self.assertEqual(keys_1, keys_2)


@parameterized_class([
   {"key_stretch_version": 1},
   {"key_stretch_version": 2},
])
class TestCoreClientSession(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):

        self.client_v2 = Client(self.server_url, key_stretch_version=2)
        self.client_v1 = Client(self.server_url, key_stretch_version=1)
        if self.key_stretch_version == 2:
            self.client = self.client_v2
        else:
            self.client = self.client_v1

        # Create a fresh testing account.
        self.acct = TestEmailAccount()
        self.session = self.client.create_account(
            email=self.acct.email,
            password=DUMMY_PASSWORD,
            keys=True,
        )
        self.stretchpwd = self.session.stretchpwd

        # Verify the account so that we can actually use the session.
        m = self.acct.wait_for_email(lambda m: "x-verify-code" in m["headers"])
        if not m:
            raise RuntimeError("Verification email was not received")
        self.acct.clear()
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

    def test_get_random_bytes(self):
        b1 = self.session.get_random_bytes()
        b2 = self.session.get_random_bytes()
        self.assertTrue(isinstance(b1, bytes))
        self.assertNotEqual(b1, b2)

    def test_change_password(self):
        # Change the password.
        newpwd = mutate_one_byte(DUMMY_PASSWORD)
        self.session.change_password(DUMMY_PASSWORD, newpwd)

        # Check that we can use the new password.
        session2 = self.client.login(self.acct.email, newpwd, keys=True)
        if not session2.get_email_status().get("verified"):
            def has_verify_code(m):
                return "x-verify-code" in m["headers"]
            m = self.acct.wait_for_email(has_verify_code)
            if not m:
                raise RuntimeError("Verification email was not received")
            self.acct.clear()
            session2.verify_email_code(m["headers"]["x-verify-code"])

        # Check that encryption keys have been preserved.
        keys = session2.fetch_keys()
        self.assertEqual(self.session.keys[0], keys[0])
        self.assertEqual(self.session.keys[1], keys[1])

    def test_totp(self):
        resp = self.session.totp_create()

        # Should exist even if not verified
        self.assertTrue(self.session.totp_exists())

        # Creating again should work unless verified
        resp = self.session.totp_create()

        # Set session unverified to test next call
        self.session.verified = False

        # Verify the code
        code = pyotp.TOTP(resp["secret"]).now()
        self.assertTrue(self.session.totp_verify(code))
        self.assertTrue(self.session.verified)

        # Should exist
        self.assertTrue(self.session.totp_exists())

        # Double create causes a client error
        with self.assertRaises(fxa.errors.ClientError):
            self.session.totp_create()

        # Remove the code
        resp = self.session.totp_delete()

        # And now should not exist
        self.assertFalse(self.session.totp_exists())


# helpers
def verify_account(acct, client):
    def wait_for_email(m):
        return "x-uid" in m["headers"] and "x-verify-code" in m["headers"]

    m = acct.wait_for_email(wait_for_email)
    if not m:
        raise RuntimeError("Verification email was not received")
    # If everything went well, verify_email_code should return an empty json object
    response = client.verify_email_code(m["headers"]["x-uid"],
                                        m["headers"]["x-verify-code"])
    return response
