# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import

from binascii import hexlify
from hashlib import sha256
import os

from requests.auth import AuthBase
from six.moves.urllib.parse import urlparse

from fxa import core
from fxa import oauth

DEFAULT_CLIENT_ID = "5882386c6d801776"  # Firefox dev Client ID


class FxABrowserIDAuth(AuthBase):
    """Handles authentication using FxA BrowserID.

    :param email:
      The user Firefox Account email address

    :param password:
      The user Firefox Account password

    :param audience:
      The audience the assertion is valid for.

    :param server_url:
      The url of the Firefox Account server.

    """
    def __init__(self, email, password, audience=None, with_client_state=False,
                 server_url=core.DEFAULT_SERVER_URL):
        self.email = email
        self.password = password
        self.audience = audience
        self.with_client_state = with_client_state
        self.server_url = server_url

    def __call__(self, request):
        client = core.Client(server_url=self.server_url)
        session = client.login(self.email, self.password, keys=True)

        if self.audience is None:
            url = urlparse(request.url)
            self.audience = "%s://%s/" % (url.scheme, url.netloc)

        bid_assertion = session.get_identity_assertion(self.audience)
        _, keyB = session.fetch_keys()
        client_state = hexlify(sha256(keyB).digest()[0:16])
        request.headers['Authorization'] = "BrowserID %s" % bid_assertion

        if self.with_client_state:
            request.headers['X-Client-State'] = client_state
        return request


# If httpie is installed, register the Firefox Account BrowserID plugin.
try:
    from httpie.plugins import AuthPlugin
except ImportError:
    pass
else:
    class FxABrowserIDPlugin(AuthPlugin):
        name = 'Firefox Account BrowserID Auth'
        auth_type = 'fxa-browserid'
        description = ('Generate a BrowserID assertion from '
                       'a Firefox Account login/password')

        def get_auth(self, fxa_id, fxa_password):
            bid_audience = os.getenv('BID_AUDIENCE')
            with_client_state = os.getenv('BID_WITH_CLIENT_STATE', False)
            return FxABrowserIDAuth(fxa_id, fxa_password, bid_audience,
                                    with_client_state)


class FxABearerTokenAuth(AuthBase):
    def __init__(self, email, password, scopes=None, client_id=None,
                 account_server_url=core.DEFAULT_SERVER_URL,
                 oauth_server_url=oauth.DEFAULT_SERVER_URL):
        self.email = email
        self.password = password

        if scopes is None:
            scopes = ['profile']

        self.scopes = scopes
        self.client_id = client_id
        self.account_server_url = account_server_url
        self.oauth_server_url = oauth_server_url

    def __call__(self, request):
        client = core.Client(server_url=self.account_server_url)
        session = client.login(self.email, self.password, keys=True)

        url = urlparse(self.oauth_server_url)
        audience = "%s://%s/" % (url.scheme, url.netloc)

        bid_assertion = session.get_identity_assertion(audience)
        oauth_client = oauth.Client(server_url=self.oauth_server_url)
        token = oauth_client.authorize_token(bid_assertion,
                                             ' '.join(self.scopes),
                                             self.client_id)
        request.headers["Authorization"] = "Bearer %s" % token
        return request


# If httpie is installed, register the Firefox Account BrowserID plugin.
try:
    from httpie.plugins import AuthPlugin
except ImportError:
    pass
else:
    class FxABearerTokenPlugin(AuthPlugin):

        name = 'Firefox Account Bearer Token Auth'
        auth_type = 'fxa-bearer'
        description = ('Generate a Bearer Token from '
                       'a Firefox Account login/password')

        def get_auth(self, fxa_id, fxa_password):
            client_id = os.getenv("FXA_CLIENT_ID", DEFAULT_CLIENT_ID)
            scopes = os.getenv("FXA_SCOPES")
            account_server_url = os.getenv("FXA_ACCOUNT_SERVER_URL",
                                           core.DEFAULT_SERVER_URL)
            oauth_server_url = os.getenv("FXA_OAUTH_SERVER_URL",
                                         oauth.DEFAULT_SERVER_URL)
            if scopes:
                scopes = scopes.split()
            return FxABearerTokenAuth(fxa_id, fxa_password, scopes, client_id,
                                      account_server_url, oauth_server_url)
