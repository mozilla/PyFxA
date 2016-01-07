# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from six import string_types

from fxa._utils import APIClient, BearerTokenAuth
from fxa.constants import PRODUCTION_URLS
from fxa.errors import OutOfProtocolError


DEFAULT_SERVER_URL = PRODUCTION_URLS['profile']
VERSION_SUFFIXES = ("/v1",)
DEFAULT_CACHE_EXPIRY = 300


class Client(object):
    """Client for talking to the Firefox Accounts Profile server"""

    def __init__(self, server_url=DEFAULT_SERVER_URL):
        if not isinstance(server_url, string_types):
            self.apiclient = server_url
        else:
            server_url = server_url.rstrip('/')
            if not server_url.endswith(VERSION_SUFFIXES):
                server_url += VERSION_SUFFIXES[0]
            self.apiclient = APIClient(server_url)

    @property
    def server_url(self):
        return self.apiclient.server_url

    def get_profile(self, token):
        """Get all profile data for the user associated with this token."""
        url = '/profile'
        resp = self.apiclient.get(url, auth=BearerTokenAuth(token))

        for field in ("uid", "email", "avatar"):
            if field not in resp:
                resp[field] = None

        return resp

    def get_email(self, token):
        """Get the email address for the user associated with this token."""
        url = '/email'
        resp = self.apiclient.get(url, auth=BearerTokenAuth(token))
        try:
            return resp["email"]
        except KeyError:
            error_msg = "email missing in profile response"
            raise OutOfProtocolError(error_msg)

    def get_uid(self, token):
        """Get the account uid for the user associated with this token."""
        url = '/uid'
        resp = self.apiclient.get(url, auth=BearerTokenAuth(token))
        try:
            return resp["uid"]
        except KeyError:
            error_msg = "uid missing in profile response"
            raise OutOfProtocolError(error_msg)

    def get_avatar_url(self, token):
        """Get the url for a user's avatar picture."""
        url = '/avatar'
        resp = self.apiclient.get(url, auth=BearerTokenAuth(token))
        try:
            return resp["url"]
        except KeyError:
            error_msg = "url missing in profile response"
            raise OutOfProtocolError(error_msg)
