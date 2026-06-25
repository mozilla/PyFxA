# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import warnings

from fxa.tests.utils import unittest
from fxa._utils import FxATokenBearerAuth, HawkTokenAuth, TOKEN_PREFIXES
from fxa.errors import TrustError


# Test vectors pinned against the HKDF derivation, shared with the
# fxa-auth-client `test/bearer.ts` vectors so the on-the-wire header format
# stays in lockstep with the auth-server parser. EXPECTED_IDS pins the derived
# id for every token kind so a regression that derived ids with the wrong HKDF
# namespace (e.g. using "sessionToken" for all kinds) would be caught.
SESSION_TOKEN = (
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)
EXPECTED_IDS = {
    "sessionToken": "c0a29dcf46174973da1378696e4c82ae10f723cf4f4d9f75e39f4ae3851595ab",
    "keyFetchToken": "70db599cec9c040b10c790418f93fe77711fdea352a59e9b02d2336136d39f68",
    "accountResetToken": "920fd5fc6cb03cabd2e6854c92d2976112e7b08728825acad1b7227874201f1f",
    "passwordForgotToken": "f108185451329f7c94aa569f9efa09c8aeaef71029d341c83839e6820b870b88",
    "passwordChangeToken": "9469deecfe3182a9573c7516650522e0d3032c467e909b64dd0d93f4d1253bde",
}


class Request:
    def __init__(self, url="https://api.example.com/v1/session/status"):
        self.method = "GET"
        self.body = ""
        self.url = url
        self.headers = {"Content-Type": "application/json"}


class TestFxATokenBearerAuth(unittest.TestCase):

    def test_prefix_map_matches_server_side(self):
        self.assertEqual(TOKEN_PREFIXES["sessionToken"], "fxs")
        self.assertEqual(TOKEN_PREFIXES["keyFetchToken"], "fxk")
        self.assertEqual(TOKEN_PREFIXES["accountResetToken"], "fxar")
        self.assertEqual(TOKEN_PREFIXES["passwordForgotToken"], "fxpf")
        self.assertEqual(TOKEN_PREFIXES["passwordChangeToken"], "fxpc")

    def test_emits_prefixed_bearer_header_for_session_token(self):
        auth = FxATokenBearerAuth(SESSION_TOKEN, "sessionToken")
        req = auth(Request())
        self.assertEqual(
            req.headers["Authorization"],
            f"Bearer fxs_{EXPECTED_IDS['sessionToken']}",
        )

    def test_derives_kind_specific_id_and_prefix_for_each_kind(self):
        for kind, prefix in TOKEN_PREFIXES.items():
            auth = FxATokenBearerAuth(SESSION_TOKEN, kind)
            header = auth(Request()).headers["Authorization"]
            # Full header pinned per kind, so a wrong-namespace derivation fails.
            self.assertEqual(header, f"Bearer {prefix}_{EXPECTED_IDS[kind]}")

    def test_does_not_sign_or_mutate_other_headers(self):
        auth = FxATokenBearerAuth(SESSION_TOKEN, "sessionToken")
        req = auth(Request())
        # Bearer is stateless: no Hawk-style Host/payload-hash munging.
        self.assertNotIn("Host", req.headers)

    def test_unknown_token_kind_raises(self):
        with self.assertRaises(ValueError):
            FxATokenBearerAuth(SESSION_TOKEN, "notARealKind")

    def test_retains_bundle_key_for_key_fetch_unbundling(self):
        # fetch_keys relies on the derived bundle_key to unbundle account/keys.
        auth = FxATokenBearerAuth(SESSION_TOKEN, "keyFetchToken")
        self.assertTrue(hasattr(auth, "bundle"))
        self.assertTrue(hasattr(auth, "unbundle"))
        self.assertEqual(len(auth.bundle_key), 32)

    def test_raises_when_token_sent_over_plaintext_http(self):
        auth = FxATokenBearerAuth(SESSION_TOKEN, "sessionToken")
        with self.assertRaises(TrustError):
            auth(Request(url="http://accounts.example.com/v1/session/status"))

    def test_no_error_over_https_or_loopback(self):
        auth = FxATokenBearerAuth(SESSION_TOKEN, "sessionToken")
        # https and loopback hosts must not raise, so local http dev works.
        auth(Request(url="https://accounts.example.com/v1/session/status"))
        auth(Request(url="http://localhost:9000/v1/session/status"))
        auth(Request(url="http://127.0.0.1:9000/v1/session/status"))
        auth(Request(url="http://0.0.0.0:9000/v1/session/status"))


class TestHawkTokenAuthAlias(unittest.TestCase):

    def test_is_a_subclass_of_the_bearer_auth(self):
        self.assertTrue(issubclass(HawkTokenAuth, FxATokenBearerAuth))

    def test_emits_deprecation_warning_but_still_works(self):
        with self.assertWarns(DeprecationWarning):
            auth = HawkTokenAuth(SESSION_TOKEN, "sessionToken")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            header = auth(Request()).headers["Authorization"]
        self.assertEqual(
            header, f"Bearer fxs_{EXPECTED_IDS['sessionToken']}"
        )
