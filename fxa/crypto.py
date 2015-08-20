# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

fxa.crypto:  low-level cryptographic routines for Firefox Accounts

"""

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import dsa

import browserid.jwt
from browserid.utils import to_hex

from six import int2byte, text_type
from six.moves import xrange


def hkdf_namespace(name, extra=None):
    """Construct a HKDF key namespace string from the given simple name.

    Each use of HKDF to derive keys from a master secret should use a unique
    string for the "info" parameter, to ensure that different keys are
    generated for different purposes.  This function prepends an application-
    specific URI to the given name components to generate a (hopefully)
    globally-unique info string.
    """
    if isinstance(name, text_type):
        name = name.encode("utf8")
    kw = b"identity.mozilla.com/picl/v1/" + name
    if extra is not None:
        kw = kw + b":" + extra
    return kw


def quick_stretch_password(email, password):
    """Perform the "quick stretch" operation on the given credentials.

    This performs a smallish number of PBKDF2 rounds on the given password.
    It's designed as a compromise between the amount of computation done by
    the client (which may be very resource constrained) and resistance to
    brute-force guessing (which would ideally demand more stretching).
    """
    if isinstance(email, text_type):
        email = email.encode("utf8")
    if isinstance(password, text_type):
        password = password.encode("utf8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_namespace(b"quickStretch", email),
        iterations=1000,
        backend=backend
    )
    return kdf.derive(password)


def derive_key(secret, namespace, size=32):
    """HKDF-derive key material from the given master secret.

    This applies standard HKDF with our application-specific defaults, to
    produce derived key material of the requested length.
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=size,
        salt=b"",
        info=hkdf_namespace(namespace),
        backend=backend
    )
    return kdf.derive(secret)


def calculate_hmac(key, data):
    """Shortcut for calculating HMAC of a string."""
    h = HMAC(
        key=key,
        algorithm=hashes.SHA256(),
        backend=backend
    )
    h.update(data)
    return h.finalize()


def verify_hmac(key, data, signature):
    """Shortcut for verifying HMAC of a string."""
    h = HMAC(
        key=key,
        algorithm=hashes.SHA256(),
        backend=backend
    )
    h.update(data)
    return h.verify(signature)


def xor(data1, data2):
    if len(data1) != len(data2):
        raise ValueError("cannot xor strings of different length")
    bs = (ord(data1[i:i+1]) ^ ord(data2[i:i+1]) for i in xrange(len(data1)))
    return b"".join(int2byte(b) for b in bs)


def bundle(key, namespace, payload):
    """Encrypt a response bundle using the given key."""
    # Derive enough key material for HMAC-check and encryption.
    size = 32 + len(payload)
    key_material = derive_key(key, namespace, size)
    # XOR-encrypt the payload using the derived key.
    xor_key = key_material[32:]
    ciphertext = xor(xor_key, payload)
    # Append an HMAC using the derived key.
    hmac_key = key_material[:32]
    return ciphertext + calculate_hmac(hmac_key, ciphertext)


def unbundle(key, namespace, payload):
    """Decrypt a response bundle using the given key."""
    # Split off the last 32 bytes, they're the HMAC.
    ciphertext = payload[:-32]
    expected_hmac = payload[-32:]
    # Derive enough key material for HMAC-check and decryption.
    size = 32 + len(ciphertext)
    key_material = derive_key(key, namespace, size)
    # Check the HMAC using the derived key.
    hmac_key = key_material[:32]
    verify_hmac(hmac_key, ciphertext, expected_hmac)
    # XOR-decrypt the ciphertext using the derived key.
    xor_key = key_material[32:]
    return xor(xor_key, ciphertext)


def generate_keypair():
    """Generate a new DSA keypair for use with PyBrowserID.

    This function returns a tuple (public_data, private_key) giving the
    JSON-serializable public-key data and the associated private key as a
    browserid.jwt.Key object.
    """
    key = dsa.generate_private_key(1024, backend=backend)
    params = key.parameters().parameter_numbers()
    data = {
        "algorithm": "DS",
        "p": to_hex(params.p),
        "q": to_hex(params.q),
        "g": to_hex(params.g),
        "y": to_hex(key.public_key().public_numbers().y),
        "x": to_hex(key.private_numbers().x),
    }
    private_key = browserid.jwt.DS128Key(data)
    del data["x"]
    return data, private_key
