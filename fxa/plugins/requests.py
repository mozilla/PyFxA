# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os

from hashlib import sha256
from requests.auth import AuthBase
from urllib.parse import urlparse

from fxa.cache import MemoryCache
from fxa.constants import PRODUCTION_URLS
from fxa.tools.bearer import get_bearer_token

FXA_ACCOUNT_URL = PRODUCTION_URLS['authentication']
FXA_OAUTH_URL = PRODUCTION_URLS['oauth']
DEFAULT_CACHE_EXPIRY = 3600
DEFAULT_CLIENT_ID = "5882386c6d801776"  # Firefox dev Client ID


def get_cache_key(*args):
    cache_key = sha256()
    for key in args:
        if key:
            cache_key.update(str(key).encode('utf-8'))
        cache_key.update(b'\n')
    return cache_key.hexdigest()

class FxABearerTokenAuth(AuthBase):
    def __init__(self, email, password, scopes=None, client_id=None,
                 account_server_url=FXA_ACCOUNT_URL,
                 oauth_server_url=FXA_OAUTH_URL,
                 cache=True, ttl=DEFAULT_CACHE_EXPIRY):
        self.email = email
        self.password = password

        if scopes is None:
            scopes = ['profile']

        self.scopes = scopes
        self.client_id = client_id
        self.account_server_url = account_server_url
        self.oauth_server_url = oauth_server_url

        self.cache = cache
        if self.cache is True:
            self.cache = MemoryCache(ttl)

    def __call__(self, request):
        cache_key = get_cache_key(
            self.account_server_url, self.oauth_server_url,
            self.email, self.password, self.scopes, self.client_id)
        token = None
        if self.cache:
            token = self.cache.get(cache_key)

        if not token:
            token = get_bearer_token(
                self.email, self.password, self.scopes,
                client_id=self.client_id,
                account_server_url=self.account_server_url,
                oauth_server_url=self.oauth_server_url)

            if self.cache:
                self.cache.set(cache_key, token)

        request.headers["Authorization"] = "Bearer %s" % token
        return request


# If httpie is installed, register the Firefox Account BearerToken plugin.
try:
    from httpie.plugins import AuthPlugin
except ImportError:
    pass
else:  # pragma: no cover
    class FxABearerTokenPlugin(AuthPlugin):

        name = 'Firefox Account Bearer Token Auth'
        auth_type = 'fxa-bearer'
        description = ('Generate a Bearer Token from '
                       'a Firefox Account login/password')

        def get_auth(self, fxa_id, fxa_password):
            client_id = os.getenv("FXA_CLIENT_ID", DEFAULT_CLIENT_ID)
            scopes = os.getenv("FXA_SCOPES")
            account_server_url = os.getenv("FXA_ACCOUNT_SERVER_URL",
                                           FXA_ACCOUNT_URL)
            oauth_server_url = os.getenv("FXA_OAUTH_SERVER_URL", FXA_OAUTH_URL)
            if scopes:
                scopes = scopes.split()
            return FxABearerTokenAuth(fxa_id, fxa_password, scopes, client_id,
                                      account_server_url, oauth_server_url)
