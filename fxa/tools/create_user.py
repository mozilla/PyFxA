# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
import base64
import os
import hmac

from fxa import core
from fxa import errors

FXA_ERROR_ACCOUNT_EXISTS = 101


def create_new_fxa_account(fxa_user_salt=None, account_server_url=None,
                           prefix="fxa", content_server_url=None):
    if account_server_url and 'stage' in account_server_url:
        if not fxa_user_salt:
            fxa_user_salt = os.urandom(36)
        else:
            fxa_user_salt = base64.urlsafe_b64decode(fxa_user_salt)

        password = hmac.new(fxa_user_salt, b"loadtest").hexdigest()
        email = "%s-%s@restmail.net" % (prefix, password)

        client = core.Client(server_url=account_server_url)

        try:
            client.create_account(email,
                                  password=password,
                                  preVerified=True)
        except errors.ClientError as e:
            if e.errno != FXA_ERROR_ACCOUNT_EXISTS:
                raise
        finally:
            return email, password
    else:
        message = ("You are not using stage (%s), make sure your FxA test "
                   "account exists: %s" % (account_server_url,
                                           content_server_url))
        raise ValueError(message)
