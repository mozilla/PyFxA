# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import base64
import os
import re
import hmac

from fxa import core
from fxa import errors
from fxa.tests.utils import TestEmailAccount

FXA_ERROR_ACCOUNT_EXISTS = 101


def create_new_fxa_account(fxa_user_salt=None, account_server_url=None,
                           prefix="fxa", content_server_url=None):
    if account_server_url and re.search('(dev)|(stage)', account_server_url):
        if not fxa_user_salt:
            fxa_user_salt = os.urandom(36)
        else:
            fxa_user_salt = base64.urlsafe_b64decode(fxa_user_salt)

        password = hmac.new(fxa_user_salt, b"loadtest", "md5").hexdigest()
        email = "%s-%s@restmail.net" % (prefix, password)

        client = core.Client(server_url=account_server_url)
        inbox = TestEmailAccount(email)
        # The address is fixed per salt, so drop codes from earlier runs.
        inbox.clear()

        try:
            session = client.create_account(email, password=password)
        except errors.ClientError as e:
            if e.errno != FXA_ERROR_ACCOUNT_EXISTS:
                raise
            return email, password

        m = inbox.wait_for_email(lambda m: "x-verify-code" in m["headers"])
        if not m:
            raise RuntimeError("Verification email was not received")
        session.verify_email_code(m["headers"]["x-verify-code"])
        return email, password
    else:
        message = ("You are not using dev or stage (%s), make sure your FxA "
                   "test account exists: %s" % (account_server_url,
                                                content_server_url))
        raise ValueError(message)
