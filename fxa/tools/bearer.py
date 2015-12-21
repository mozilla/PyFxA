# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
from six.moves.urllib.parse import urlparse
from fxa import core
from fxa import oauth

DEFAULT_CLIENT_ID = "5882386c6d801776"  # Firefox dev Client ID
FXA_API_URL = "https://api-accounts.stage.mozaws.net/v1"
FXA_OAUTH_URL = "https://oauth.stage.mozaws.net/v1"


def get_bearer_token(email, password, scopes=None,
                     account_server_url=FXA_API_URL,
                     oauth_server_url=FXA_OAUTH_URL,
                     client_id=DEFAULT_CLIENT_ID):

    if scopes is None:
        scopes = ['profile']

    client = core.Client(server_url=account_server_url)
    session = client.login(email, password)

    url = urlparse(oauth_server_url)
    audience = "%s://%s/" % (url.scheme, url.netloc)

    bid_assertion = session.get_identity_assertion(audience)
    oauth_client = oauth.Client(server_url=oauth_server_url)
    token = oauth_client.authorize_token(bid_assertion,
                                         ' '.join(scopes),
                                         client_id)
    return token
