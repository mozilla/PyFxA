# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import re

from parameterized import parameterized

from binascii import unhexlify

from fxa.crypto import (
    quick_stretch_password,
    stretch_password,
    derive_key,
    bundle,
    unbundle,
    hkdf_namespace,
    xor
)

from fxa.tests.utils import (
    unittest,
    mutate_one_byte,
    DUMMY_EMAIL,
    DUMMY_PASSWORD,
    DUMMY_SALT_V2,
)


def dehexlify(hexbytes):
    """Unhexlify after removing whitespace.

    This is handy for converting copy-pasted test vectors (which are usually
    nicely-spaced hexadecimal strings for readabilty) into bytes objects
    for direct comparison with computed results.
    """
    return unhexlify(re.sub(r"\s", "", hexbytes))


class TestCoreCrypto(unittest.TestCase):

    @parameterized.expand([
       (
           1,
           "andr\xe9@example.org",
           "e4e8889bd8bd61ad 6de6b95c059d56e7 b50dacdaf62bd846 44af7e2add84345d",
           "247b675ffb4c4631 0bc87e26d712153a be5e1c90ef00a478 4594f97ef54f2375",
           "de6a2648b78284fc b9ffa81ba9580330 9cfba7af583c01a8 a1a63e567234dd28"
        ),
       (
           2,
           b'c2dc400c9cc1a93dd3cd3af1b05ebd60',
           "b38b6a81c851c343 43899bb1c64bd179 cdddea8402608494 44b0b91b413a80de",
           "28c81379c31905d1 6f9aa9c63fcf0950 094e413e16a9c9be 41f52dbb09af518e",
           "e1c1f362437c8977 e2ad8372cafcaf87 3df7dce30ae351bc d262af05e84caa92"
        ),
    ])
    def test_password_stretching_and_key_derivation(
        self,
        key_stretch_version,
        salt,
        expected_qspwd,
        expected_authpw,
        expected_ubkey
    ):
        pwd = "p\xe4ssw\xf6rd"
        self.assertEqual(pwd.encode("utf8"), dehexlify("""
            70c3a4737377c3b6 7264
        """))
        if key_stretch_version == 2:
            qspwd = stretch_password(salt, pwd)
        else:
            qspwd = quick_stretch_password(salt, pwd)

        authpw = derive_key(qspwd, "authPW")
        ubkey = derive_key(qspwd, "unwrapBkey")

        self.assertEqual(qspwd, dehexlify(expected_qspwd))
        self.assertEqual(authpw, dehexlify(expected_authpw))
        self.assertEqual(ubkey, dehexlify(expected_ubkey))

    @parameterized.expand([
       (1, unhexlify("59eb52f6ee5ebe2b599161aaa9b171c3baa8bed594d4e2a8b4b539fb9eba8368")),
       (2, unhexlify("570b9e5d11640357648fc9dcda78b767fc3676393016391762a21133d291fd1d")),
    ])
    def test_dummy_credentials(self, key_stretch_version, expected_stretched_password):
        if key_stretch_version == 2:
            qspwd = stretch_password(DUMMY_SALT_V2, DUMMY_PASSWORD)
        else:
            qspwd = quick_stretch_password(DUMMY_EMAIL, DUMMY_PASSWORD)

        self.assertEqual(qspwd, expected_stretched_password)

    def test_bundle_and_unbundle(self):
        key = os.urandom(32)
        payload = os.urandom(47)
        enc_payload = bundle(key, b"test-namespace", payload)
        dec_payload = unbundle(key, b"test-namespace", enc_payload)
        self.assertEqual(payload, dec_payload)
        # Modified ciphertext should fail HMAC check.
        bad_enc_payload = mutate_one_byte(enc_payload)
        with self.assertRaises(Exception):
            unbundle(key, b"test-namespace", bad_enc_payload)

    def test_xor(self):
        self.assertEqual(xor(b"", ""), b"")
        self.assertEqual(xor(b"\x01", b"\x01"), b"\x00")
        self.assertEqual(xor(b"\x01", b"\x02"), b"\x03")
        self.assertEqual(xor(b"abc", b"def"), b"\x05\x07\x05")
        with self.assertRaises(ValueError):
            xor(b"shorter", b"longer string")

    def test_hkdf_namespace_handle_unicode_strings(self):
        kw = hkdf_namespace("foobar")
        self.assertEqual(kw, b"identity.mozilla.com/picl/v1/foobar")

    def test_hkdf_namespace_handle_bytes_strings(self):
        kw = hkdf_namespace(b"foobar")
        self.assertEqual(kw, b"identity.mozilla.com/picl/v1/foobar")
