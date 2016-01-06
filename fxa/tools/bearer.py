# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
from six.moves.urllib.parse import urlparse
from fxa import core
from fxa import oauth


def get_bearer_token(email, password, scopes=None,
                     account_server_url=None,
                     oauth_server_url=None,
                     client_id=None):

    message = None

    if not account_server_url:
        message = 'Please define an account_server_url.'

    elif not oauth_server_url:
        message = 'Please define an oauth_server_url.'

    elif not client_id:
        message = 'Please define a client_id.'

    if message:
        raise ValueError(message)

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
