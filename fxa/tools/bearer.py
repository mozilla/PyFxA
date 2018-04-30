# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import absolute_import
from fxa import core
from fxa import oauth


def get_bearer_token(email, password, scopes=None,
                     account_server_url=None,
                     oauth_server_url=None,
                     client_id=None,
                     client_secret=None,
                     use_pkce=False,
                     unblock_code=None):

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
    session = client.login(email, password, unblock_code=unblock_code)

    oauth_client = oauth.Client(client_id, client_secret,
                                server_url=oauth_server_url)

    # XXX TODO: we should be able to automaticaly choose the most
    # direct route to getting a token, based on registered client
    # metadata.  Unfortunately the oauth-server doesn't (yet) expose
    # client properties like `canGrant` and `isPublic`.
    # print metadata
    # metadata = oauth_client.get_client_metadata()

    scope = ' '.join(scopes)
    if client_secret is None and not use_pkce:
        token = oauth_client.authorize_token(session, scope)
    else:
        challenge = verifier = {}
        if use_pkce:
            (challenge, verifier) = oauth_client.generate_pkce_challenge()
        code = oauth_client.authorize_code(session, scope, **challenge)
        token = oauth_client.trade_code(code, **verifier)

    return token
