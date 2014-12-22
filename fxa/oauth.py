# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from fxa.errors import OutOfProtocolError
from fxa._utils import APIClient


DEFAULT_SERVER_URL = "https://oauth.accounts.firefox.com"


class Client(object):
    """Client for talking to the Firefox Authentication server"""

    def __init__(self, server_url=None):
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        if isinstance(server_url, basestring):
            self.apiclient = APIClient(server_url)
        else:
            self.apiclient = server_url

    def trade_code(self, client_id, client_secret, code):
        """Trade the authentication code for a longer lived token."""
        url = '/v1/token'
        body = {
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret
        }
        resp = self.apiclient.post(url, body)

        if 'access_token' not in resp:
            error_msg = 'access_token missing in OAuth response'
            raise OutOfProtocolError(error_msg)

        return resp['access_token']

    def verify_token(self, token):
        """Verify a OAuth token, and retrieve user id and scopes."""
        url = '/v1/verify'
        body = {
            'token': token
        }
        resp = self.apiclient.post(url, body)

        missing_attrs = ", ".join([k for k in ('user', 'scope', 'client_id')
                                   if k not in resp])
        if missing_attrs:
            error_msg = '{} missing in OAuth response'.format(missing_attrs)
            raise OutOfProtocolError(error_msg)

        return resp
