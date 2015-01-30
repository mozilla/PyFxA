# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from six import string_types

from fxa.errors import OutOfProtocolError, ScopeMismatchError
from fxa._utils import APIClient, scope_matches


DEFAULT_SERVER_URL = "https://oauth.accounts.firefox.com"


class Client(object):
    """Client for talking to the Firefox Accounts OAuth server"""

    def __init__(self, client_id=None, client_secret=None, server_url=None):
        self.client_id = client_id
        self.client_secret = client_secret
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        if isinstance(server_url, string_types):
            self.apiclient = APIClient(server_url)
        else:
            self.apiclient = server_url

    def trade_code(self, code, client_id=None, client_secret=None):
        """Trade the authentication code for a longer lived token.

        :param code: the authentication code from the oauth redirect dance.
        :param client_id: the string generated during FxA client registration.
        :param client_secret: the related secret string.
        :returns: a dict with user id and authorized scopes for this token.
        """
        if client_id is None:
            client_id = self.client_id
        if client_secret is None:
            client_secret = self.client_secret
        url = '/token'
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

    def verify_token(self, token, scope=None):
        """Verify an OAuth token, and retrieve user id and scopes.

        :param token: the string to verify.
        :param scope: optional scope expected to be provided for this token.
        :returns: a dict with user id and authorized scopes for this token.
        :raises fxa.errors.ClientError: if the provided token is invalid.
        :raises fxa.errors.TrustError: if the token scopes do not match.
        """
        url = '/verify'
        body = {
            'token': token
        }
        resp = self.apiclient.post(url, body)

        missing_attrs = ", ".join([k for k in ('user', 'scope', 'client_id')
                                   if k not in resp])
        if missing_attrs:
            error_msg = '{0} missing in OAuth response'.format(missing_attrs)
            raise OutOfProtocolError(error_msg)

        if scope is not None:
            authorized_scope = resp['scope']
            if not scope_matches(authorized_scope, scope):
                raise ScopeMismatchError(authorized_scope, scope)

        return resp
