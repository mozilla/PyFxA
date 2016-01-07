# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import os
import re
from binascii import unhexlify
from six import text_type

from fxa.crypto import (
    quick_stretch_password,
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
    DUMMY_STRETCHED_PASSWORD,
)


def dehexlify(hexbytes):
    """Unhexlify after removing whitespace.

    This is handy for converting copy-pasted test vectors (which are usually
    nicely-spaced hexadecimal strings for readabilty) into bytes objects
    for direct comparison with computed results.
    """
    return unhexlify(re.sub(r"\s", "", hexbytes))


class TestCoreCrypto(unittest.TestCase):

    def test_password_stretching_and_key_derivation(self):
        # These are the test vectors from the onepw protocol document.
        email = u"andr\xe9@example.org"
        self.assertEqual(email.encode("utf8"), dehexlify("""
            616e6472c3a94065 78616d706c652e6f 7267
        """))
        pwd = u"p\xe4ssw\xf6rd"
        self.assertEqual(pwd.encode("utf8"), dehexlify("""
            70c3a4737377c3b6 7264
        """))
        qspwd = quick_stretch_password(email, pwd)
        self.assertEqual(qspwd, dehexlify("""
            e4e8889bd8bd61ad 6de6b95c059d56e7 b50dacdaf62bd846 44af7e2add84345d
        """))
        authpw = derive_key(qspwd, "authPW")
        self.assertEqual(authpw, dehexlify("""
            247b675ffb4c4631 0bc87e26d712153a be5e1c90ef00a478 4594f97ef54f2375
        """))
        ubkey = derive_key(qspwd, "unwrapBkey")
        self.assertEqual(ubkey, dehexlify("""
            de6a2648b78284fc b9ffa81ba9580330 9cfba7af583c01a8 a1a63e567234dd28
        """))

    def test_dummy_credentials(self):
        qspwd = quick_stretch_password(DUMMY_EMAIL, DUMMY_PASSWORD)
        self.assertEqual(qspwd, DUMMY_STRETCHED_PASSWORD)

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
        kw = hkdf_namespace(text_type("foobar"))
        self.assertEquals(kw, b"identity.mozilla.com/picl/v1/foobar")

    def test_hkdf_namespace_handle_bytes_strings(self):
        kw = hkdf_namespace("foobar".encode('utf-8'))
        self.assertEquals(kw, b"identity.mozilla.com/picl/v1/foobar")
