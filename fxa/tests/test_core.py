# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import time

from six import binary_type
from six.moves.urllib.parse import urlparse

import pyotp
import pytest

from browserid import jwt
import browserid.tests.support
import browserid.utils

import fxa.errors
from fxa.core import Client
from fxa.crypto import quick_stretch_password

from fxa.tests.utils import (
    unittest,
    mutate_one_byte,
    TestEmailAccount,
    DUMMY_PASSWORD,
    DUMMY_STRETCHED_PASSWORD,
)


# XXX TODO: this currently talks to a live server by default.
# It's nice to have such an option, but we shouldn't hit the network
# for every test run.  Instead let's build a mock server and use that.
TEST_SERVER_URL = "https://api-accounts.stage.mozaws.net/v1/"


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

    def test_account_login(self):
        acct = TestEmailAccount()
        session1 = self.client.create_account(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )
        self._accounts_to_delete.append(acct)
        session2 = self.client.login(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )
        self.assertEqual(session1.email, session2.email)
        self.assertNotEqual(session1.token, session2.token)

    def test_get_random_bytes(self):
        b1 = self.client.get_random_bytes()
        b2 = self.client.get_random_bytes()
        self.assertTrue(isinstance(b1, binary_type))
        self.assertNotEqual(b1, b2)

    @pytest.mark.skip(reason="This tests keeps getting rate limited....")
    def test_resend_verify_code(self):
        acct = TestEmailAccount()
        session = self.client.create_account(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )
        self._accounts_to_delete.append(acct)

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
        self.client.create_account(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )
        self._accounts_to_delete.append(acct)

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
            stretchpwd=DUMMY_STRETCHED_PASSWORD
        )

    def test_email_code_verification(self):
        self.client = Client(self.server_url)
        # Create a fresh testing account.
        self.acct = TestEmailAccount()
        self.client.create_account(
            email=self.acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )

        def wait_for_email(m):
            return "x-uid" in m["headers"] and "x-verify-code" in m["headers"]

        m = self.acct.wait_for_email(wait_for_email)
        if not m:
            raise RuntimeError("Verification email was not received")
        # If everything went well, verify_email_code should return an empty json object
        response = self.client.verify_email_code(m["headers"]["x-uid"],
                                                 m["headers"]["x-verify-code"])
        self.assertEqual(response, {})

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_send_unblock_code(self):
        acct = TestEmailAccount(email="block-{uniq}@{hostname}")
        self.client.create_account(
            email=acct.email,
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
        )
        self._accounts_to_delete.append(acct)

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
            stretchpwd=DUMMY_STRETCHED_PASSWORD,
            unblock_code=code
        )


class TestCoreClientSession(unittest.TestCase):

    server_url = TEST_SERVER_URL

    def setUp(self):
        self.client = Client(self.server_url)
        # Create a fresh testing account.
        self.acct = TestEmailAccount()
        self.stretchpwd = quick_stretch_password(
            self.acct.email,
            DUMMY_PASSWORD,
        )
        self.session = self.client.create_account(
            email=self.acct.email,
            stretchpwd=self.stretchpwd,
            keys=True,
        )
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
        self.assertTrue(isinstance(b1, binary_type))
        self.assertNotEqual(b1, b2)

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_sign_certificate(self):
        email = self.acct.email
        pubkey = browserid.tests.support.get_keypair(email)[0]
        cert = self.session.sign_certificate(pubkey)
        issuer = browserid.utils.decode_json_bytes(cert.split(".")[1])["iss"]
        expected_issuer = urlparse(self.client.server_url).hostname
        self.assertEqual(issuer, expected_issuer)

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_sign_certificate_handles_duration(self):
        email = self.acct.email
        pubkey = browserid.tests.support.get_keypair(email)[0]
        millis = int(round(time.time() * 1000))
        cert = self.session.sign_certificate(pubkey, duration=4000)
        cert_exp = browserid.utils.decode_json_bytes(cert.split(".")[1])["exp"]
        ttl = round(float(cert_exp - millis) / 1000)
        self.assertGreaterEqual(ttl, 2)
        self.assertLessEqual(ttl, 30)

    def test_change_password(self):
        # Change the password.
        newpwd = mutate_one_byte(DUMMY_PASSWORD)
        self.stretchpwd = quick_stretch_password(self.acct.email, newpwd)
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
        session2.fetch_keys()
        self.assertEqual(self.session.keys, session2.keys)

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_get_identity_assertion(self):
        assertion = self.session.get_identity_assertion("http://example.com")
        data = browserid.verify(assertion, audience="http://example.com")
        self.assertEqual(data["status"], "okay")
        expected_issuer = urlparse(self.session.server_url).hostname
        self.assertEqual(data["issuer"], expected_issuer)
        expected_email = "{0}@{1}".format(self.session.uid, expected_issuer)
        self.assertEqual(data["email"], expected_email)

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_get_identity_assertion_handles_duration(self):
        millis = int(round(time.time() * 1000))
        bid_assertion = self.session.get_identity_assertion(
            "http://example.com", 1234)
        cert, assertion = browserid.utils.unbundle_certs_and_assertion(
            bid_assertion)
        cert = jwt.parse(cert[0]).payload
        assertion = jwt.parse(assertion).payload

        # Validate cert expiry
        ttl = round(float(cert['exp'] - millis) / 1000)
        self.assertGreaterEqual(ttl, 1230)
        self.assertLessEqual(ttl, 1260)

        # Validate assertion expiry
        ttl = round(float(assertion['exp'] - millis) / 1000)
        self.assertGreaterEqual(ttl, 1230)
        self.assertLessEqual(ttl, 1260)

    @pytest.mark.skip(reason="This endpoint is no longer supported.")
    def test_get_identity_assertion_accepts_service(self):
        # We can't observe any side-effects of sending the service query param,
        # but we can test that it doesn't error out.
        assertion = self.session.get_identity_assertion("http://example.com",
                                                        service="test-me")
        data = browserid.verify(assertion, audience="http://example.com")
        self.assertEqual(data["status"], "okay")

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
