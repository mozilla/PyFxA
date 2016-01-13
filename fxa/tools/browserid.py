# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
from binascii import hexlify
from hashlib import sha256

from fxa import core


def get_browserid_assertion(email, password, audience,
                            account_server_url=None,
                            duration=core.DEFAULT_ASSERTION_DURATION):
    if not account_server_url:
        message = 'Please define an account_server_url.'
        raise ValueError(message)

    client = core.Client(server_url=account_server_url)
    session = client.login(email, password, keys=True)

    bid_assertion = session.get_identity_assertion(
        audience=audience, duration=duration)
    _, keyB = session.fetch_keys()
    client_state = hexlify(sha256(keyB).digest()[0:16]).decode('utf-8')

    return bid_assertion, client_state
