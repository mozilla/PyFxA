# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import json
import os
import time

from urllib.parse import urlparse

import pyotp
import pytest
import requests
import responses
from parameterized import parameterized_class

import fxa.errors
from fxa.core import Client, PasswordForgotToken, Session, StretchedPassword
from fxa._utils import APIClient, FxATokenBearerAuth

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
        if not os.environ.get("FXA_RUN_LIVE_TESTS"):
            self.skipTest("Set FXA_RUN_LIVE_TESTS=1 to run live tests against the stage server")
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
        # send_otp treats an unverified account as unknown.
        verify_account(acct, self.client)
        acct.clear()

        # Initiate the password reset flow, and grab the one-time code.
        pftok = self.client.send_reset_code(acct.email, service="foobar")
        m = acct.wait_for_email(lambda m: "x-password-forgot-otp" in m["headers"])
        if not m:
            raise RuntimeError("Password reset email was not received")
        acct.clear()
        code = m["headers"]["x-password-forgot-otp"]

        # Try with an invalid code to test error handling.
        with self.assertRaises(fxa.errors.ClientError):
            pftok.verify_code(mutate_one_byte(code))
        self.assertIsNone(pftok.token)

        # Re-send the code, as if we've lost the email.
        pftok.resend_code()
        m = acct.wait_for_email(lambda m: "x-password-forgot-otp" in m["headers"])
        if not m:
            raise RuntimeError("Password reset email was not received")
        code = m["headers"]["x-password-forgot-otp"]

        # Now verify with the actual code, and reset the account.
        artok = pftok.verify_code(code)
        self.assertIsNotNone(pftok.token)
        self.assertEqual(pftok.uid, session.uid)
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
        if not os.environ.get("FXA_RUN_LIVE_TESTS"):
            self.skipTest("Set FXA_RUN_LIVE_TESTS=1 to run live tests against the stage server")
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
        # TOTP setup is guarded by a short-lived MFA token, obtained by
        # verifying a code the server emails to the account.
        self.session.mfa_request_otp("2fa")
        m = self.acct.wait_for_email(
            lambda m: "x-account-change-verify-code" in m["headers"])
        if not m:
            raise RuntimeError("MFA code email was not received")
        self.acct.clear()
        mfa_token = self.session.mfa_verify_otp(
            m["headers"]["x-account-change-verify-code"], "2fa")

        resp = self.session.totp_create(mfa_token)

        # Nothing is stored on the account until setup completes.
        self.assertFalse(self.session.totp_exists())

        # Creating again re-issues the same pending secret.
        resp2 = self.session.totp_create(mfa_token)
        self.assertEqual(resp2["secret"], resp["secret"])

        code = pyotp.TOTP(resp["secret"]).now()
        self.assertTrue(self.session.totp_setup_verify(mfa_token, code))
        self.assertTrue(self.session.totp_setup_complete(mfa_token))
        self.assertTrue(self.session.totp_exists())

        # Creating again once TOTP is enabled is a client error.
        with self.assertRaises(fxa.errors.ClientError):
            self.session.totp_create(mfa_token)

        # Remove the code
        self.session.totp_delete(mfa_token)

        # And now should not exist
        self.assertFalse(self.session.totp_exists())


class TestAPIClientWAFHeader(unittest.TestCase):
    """Unit tests for CI_WAF_TOKEN header injection in APIClient."""

    SERVER_URL = "https://api.example.com/v1/"

    def test_waf_header_set_when_env_var_present(self):
        with unittest.mock.patch.dict("os.environ", {"CI_WAF_TOKEN": "sekrit"}):
            client = APIClient(self.SERVER_URL)
        self.assertEqual(client.headers.get("fxa-ci"), "sekrit")

    def test_waf_header_absent_when_env_var_not_set(self):
        env = {k: v for k, v in os.environ.items() if k != "CI_WAF_TOKEN"}
        with unittest.mock.patch.dict("os.environ", env, clear=True):
            client = APIClient(self.SERVER_URL)
        self.assertNotIn("fxa-ci", client.headers)

    def test_waf_header_set_on_caller_supplied_session(self):
        supplied = requests.Session()
        with unittest.mock.patch.dict("os.environ", {"CI_WAF_TOKEN": "sekrit"}):
            APIClient(self.SERVER_URL, session=supplied)
        self.assertEqual(supplied.headers.get("fxa-ci"), "sekrit")


class TestCoreBearerAuthHeaders(unittest.TestCase):
    """Mocked coverage that the migrated call sites send a prefixed Bearer
    header with the right per-kind prefix (live tests are gated behind
    FXA_RUN_LIVE_TESTS, so this is what guards the wire format in CI).
    """

    server_url = "https://server/v1"

    def setUp(self):
        self.client = Client(self.server_url)

    @responses.activate
    def test_session_token_call_site_sends_fxs_bearer(self):
        responses.add(responses.GET, self.server_url + "/session/status",
                      json={"uid": "abc123"}, content_type="application/json")
        session = Session(
            client=self.client, email="test@example.com",
            stretchpwd=b"\x00" * 32, uid="abc123", token="1234",
        )
        session.check_session_status()
        authz = responses.calls[0].request.headers["Authorization"]
        self.assertRegex(authz, r"^Bearer fxs_[0-9a-f]{64}$")

    @responses.activate
    def test_password_forgot_token_call_site_sends_fxpf_bearer(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/verify_code",
                      json={"accountResetToken": "ab" * 32},
                      content_type="application/json")
        self.client.verify_reset_code("1234", "deadbeef")
        authz = responses.calls[0].request.headers["Authorization"]
        self.assertRegex(authz, r"^Bearer fxpf_[0-9a-f]{64}$")

    @responses.activate
    def test_password_change_start_sends_fxs_bearer(self):
        responses.add(responses.POST, self.server_url + "/password/change/start",
                      json={}, content_type="application/json")
        session = Session(
            client=self.client, email="test@example.com",
            stretchpwd=b"\x00" * 32, uid="abc123", token="1234",
        )
        session.start_password_change(b"\x00" * 32)
        authz = responses.calls[0].request.headers["Authorization"]
        self.assertRegex(authz, r"^Bearer fxs_[0-9a-f]{64}$")

    @responses.activate
    def test_password_change_finish_adopts_replacement_session(self):
        responses.add(responses.POST, self.server_url + "/password/change/finish",
                      json={"uid": "abc123", "sessionToken": "ab" * 32},
                      content_type="application/json")
        session = Session(
            client=self.client, email="test@example.com",
            stretchpwd=b"\x00" * 32, uid="abc123", token="1234",
        )
        old_id = FxATokenBearerAuth("1234", "sessionToken").id
        session.finish_password_change("5678", b"\x00" * 32, b"\x00" * 32)
        self.assertEqual(json.loads(responses.calls[0].request.body)["sessionToken"], old_id)
        self.assertEqual(session.token, "ab" * 32)
        self.assertEqual(session._auth.id, FxATokenBearerAuth("ab" * 32, "sessionToken").id)

    @responses.activate
    def test_totp_setup_sends_plain_bearer_mfa_token(self):
        responses.add(responses.POST, self.server_url + "/mfa/totp/create",
                      json={"secret": "s", "qrCodeUrl": "data:"},
                      content_type="application/json")
        session = Session(
            client=self.client, email="test@example.com",
            stretchpwd=b"\x00" * 32, uid="abc123", token="1234",
        )
        session.totp_create("eyJ.mfa.jwt")
        authz = responses.calls[0].request.headers["Authorization"]
        self.assertEqual(authz, "Bearer eyJ.mfa.jwt")

    @responses.activate
    def test_mfa_and_totp_call_sites(self):
        session = Session(
            client=self.client, email="test@example.com",
            stretchpwd=b"\x00" * 32, uid="abc123", token="1234",
        )
        # (method call, route, response, expected return, expected body, auth)
        cases = [
            (lambda: session.mfa_request_otp("2fa"), "/mfa/otp/request",
             {}, {}, {"action": "2fa"}, r"^Bearer fxs_[0-9a-f]{64}$"),
            (lambda: session.mfa_verify_otp("123456", "2fa"), "/mfa/otp/verify",
             {"accessToken": "eyJ.mfa.jwt"}, "eyJ.mfa.jwt",
             {"code": "123456", "action": "2fa"}, r"^Bearer fxs_[0-9a-f]{64}$"),
            (lambda: session.totp_setup_verify("eyJ.mfa.jwt", "654321"),
             "/mfa/totp/setup/verify", {"success": True}, True,
             {"code": "654321"}, r"^Bearer eyJ\.mfa\.jwt$"),
            (lambda: session.totp_setup_complete("eyJ.mfa.jwt"),
             "/mfa/totp/setup/complete", {"success": True}, True,
             {}, r"^Bearer eyJ\.mfa\.jwt$"),
            (lambda: session.totp_delete("eyJ.mfa.jwt"), "/mfa/totp/destroy",
             {}, {}, {}, r"^Bearer eyJ\.mfa\.jwt$"),
        ]
        for call, route, resp, expected, body, authz in cases:
            with self.subTest(route=route):
                responses.add(responses.POST, self.server_url + route,
                              json=resp, content_type="application/json")
                self.assertEqual(call(), expected)
                req = responses.calls[-1].request
                self.assertEqual(json.loads(req.body), body)
                self.assertRegex(req.headers["Authorization"], authz)


class TestCorePasswordReset(unittest.TestCase):
    """Mocked coverage of the OTP password-reset flow and its request shapes."""

    server_url = "https://server/v1"

    def setUp(self):
        self.client = Client(self.server_url)

    @responses.activate
    def test_send_reset_code_posts_otp_request(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/send_otp",
                      json={}, content_type="application/json")
        pftok = self.client.send_reset_code("test@example.com", service="sync")
        body = json.loads(responses.calls[0].request.body)
        self.assertEqual(body, {"email": "test@example.com", "service": "sync"})
        self.assertNotIn("Authorization", responses.calls[0].request.headers)
        self.assertEqual(pftok.email, "test@example.com")
        self.assertEqual(pftok.service, "sync")
        self.assertIsNone(pftok.token)

    @responses.activate
    def test_send_reset_code_omits_service_when_unset(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/send_otp",
                      json={}, content_type="application/json")
        self.client.send_reset_code("test@example.com")
        body = json.loads(responses.calls[0].request.body)
        self.assertEqual(body, {"email": "test@example.com"})

    @responses.activate
    def test_verify_code_chains_otp_and_code_verification(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/verify_otp",
                      json={
                          "code": "c0de" * 8,
                          "token": "12" * 32,
                          "uid": "abc123",
                          "emailToHashWith": "primary@example.com",
                      }, content_type="application/json")
        responses.add(responses.POST, self.server_url + "/password/forgot/verify_code",
                      json={"accountResetToken": "ab" * 32},
                      content_type="application/json")
        pftok = PasswordForgotToken(self.client, "test@example.com")

        artok = pftok.verify_code("12345678")

        self.assertEqual(artok, "ab" * 32)
        otp_req, code_req = responses.calls[0].request, responses.calls[1].request
        self.assertEqual(json.loads(otp_req.body),
                         {"email": "test@example.com", "code": "12345678"})
        self.assertNotIn("Authorization", otp_req.headers)
        self.assertEqual(json.loads(code_req.body), {"code": "c0de" * 8})
        self.assertRegex(code_req.headers["Authorization"], r"^Bearer fxpf_[0-9a-f]{64}$")
        self.assertEqual(pftok.token, "12" * 32)
        self.assertEqual(pftok.uid, "abc123")
        self.assertEqual(pftok.email_to_hash_with, "primary@example.com")

    @responses.activate
    def test_invalid_otp_leaves_token_unset(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/verify_otp",
                      json={"code": 400, "errno": 105, "error": "Bad Request",
                            "message": "Invalid verification code"},
                      status=400, content_type="application/json")
        pftok = PasswordForgotToken(self.client, "test@example.com")
        with self.assertRaises(fxa.errors.ClientError):
            pftok.verify_code("00000000")
        self.assertIsNone(pftok.token)
        self.assertEqual(len(responses.calls), 1)

    @responses.activate
    def test_resend_code_posts_otp_request_again(self):
        responses.add(responses.POST, self.server_url + "/password/forgot/send_otp",
                      json={}, content_type="application/json")
        pftok = PasswordForgotToken(self.client, "test@example.com", service="sync")
        pftok.resend_code()
        body = json.loads(responses.calls[0].request.body)
        self.assertEqual(body, {"email": "test@example.com", "service": "sync"})


class TestCoreCreateAccount(unittest.TestCase):

    @responses.activate
    def test_removed_preverify_keywords_raise_before_request(self):
        client = Client("https://server/v1")
        for kwarg in ("preVerified", "preVerifyToken"):
            with self.subTest(kwarg=kwarg):
                with self.assertRaises(TypeError):
                    client.create_account("test@example.com", "password", **{kwarg: True})
        self.assertEqual(len(responses.calls), 0)


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
