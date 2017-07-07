# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import
from fxa import core


def send_unblock_code(email, account_server_url=None):
    if not account_server_url:
        raise ValueError('Please define an account_server_url.')

    client = core.Client(server_url=account_server_url)
    return client.send_unblock_code(email)
