# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

fxa._utils:  miscellaneous low-level utilities for PyFxA

This private-api stuff that will most likely change, move, refactor
etc as we go.  So don't import any of it outside of this package.

"""
from __future__ import absolute_import
import os
import time
import hashlib
import hmac
from binascii import hexlify, unhexlify
from base64 import b64encode
try:
    import cPickle as pickle
except ImportError:  # pragma: no cover
    import pickle

from six import PY3
from six.moves.urllib.parse import urlparse, urljoin

import requests
import requests.auth
import requests.utils
import hawkauthlib

import fxa
import fxa.errors
import fxa.crypto


# Send a custom user-agent header
# so we're easy to identify in server logs etc.

USER_AGENT_HEADER = ' '.join((
    'Mozilla/5.0 (Mobile; Firefox Accounts; rv:1.0)',
    'PyFxA/%s' % (fxa.__version__),
    requests.utils.default_user_agent(),
))


if not PY3:
    hexstr = hexlify
else:  # pragma: no cover
    def hexstr(data):
        """Like binascii.hexlify, but always returns a str instance."""
        return hexlify(data).decode("ascii")


def uniq(size=10):
    """Generate a short random hex string."""
    return hexstr(os.urandom(size // 2 + 1))[:size]


def get_hmac(data, secret, algorithm=hashlib.sha256):
    """Generate an hexdigest hmac for given data, secret and algorithm."""
    return hmac.new(secret.encode('utf-8'),
                    data.encode('utf-8'),
                    algorithm).hexdigest()


def scope_matches(provided, required):
    """Check that required scopes match the ones provided. This is used during
    token verification to raise errors if expected scopes are not met.

    :note:

        Sub-scopes are expressed using semi-colons.

        A required sub-scope will always match if its root-scope is among those
        provided (e.g. ``profile:avatar`` will match ``profile`` if provided).

    :param provided: list of scopes provided for the current token.
    :param required: the scope required (e.g. by the application).
    :returns: ``True`` if all required scopes are provided, ``False`` if not.
    """
    if not isinstance(required, (list, tuple)):
        required = [required]

    def split_subscope(s):
        return tuple((s.split(':') + [None])[:2])

    provided = set([split_subscope(p) for p in provided])
    required = set([split_subscope(r) for r in required])

    root_provided = set([root for (root, sub) in provided])
    root_required = set([root for (root, sub) in required])

    if not root_required.issubset(root_provided):
        return False

    for (root, sub) in required:
        if (root, None) in provided:
            provided.add((root, sub))

    return required.issubset(provided)


class APIClient(object):
    """A requests.Session wrapper specialized for FxA API access.

    An instance of this class should be used for making requests to an FxA
    web API endpoint.  It wraps a requests.Session instance and provides
    a broadly similar interface, with some additional functionality that's
    specific to Firefox Accounts:

        * default base server URL
        * backoff protocol support
        * sensible request timeouts
        * timestamp skew tracking with automatic retry on clockskew error

    """

    def __init__(self, server_url, session=None):
        if session is None:
            session = requests.Session()
        # Properties that can be customized to change behaviour.
        self.server_url = server_url
        self.timeout = 30
        self.max_retry_after = None
        # Internal state.
        self._session = session
        self._backoff_until = 0
        self._backoff_response = None
        self._clockskew = None

    # Reflect useful properties of the wrapped Session object.

    @property
    def headers(self):
        return self._session.headers

    @headers.setter
    def headers(self, value):
        self._session.headers = value

    @property
    def auth(self):
        return self._session.auth

    @auth.setter
    def auth(self, value):
        if getattr(value, "apiclient", None) is None:
            value.apiclient = self
        self._session.auth = value

    @property
    def hooks(self):
        return self._session.hooks

    @hooks.setter
    def hooks(self, value):
        self._session.hooks = value

    @property
    def verify(self):
        return self._session.verify

    @verify.setter
    def verify(self, value):
        self._session.verify = value

    # Add some handy utility methods of our own.

    def client_curtime(self):
        """Get the current timestamp, as seen by the client.

        This is a helper function that returns the current local time.
        It's mostly here for symmetry with server_curtime() and to assist
        in testability of this class.
        """
        return time.time()

    def server_curtime(self):
        """Get the current timestamp, as seen by the server.

        This is a helper function that automatically applies any detected
        clock-skew, to report what the current timestamp is on the server
        instead of on the client.
        """
        return self.client_curtime() + (self._clockskew or 0)

    # The actual request-making stuff.

    def request(self, method, url, json=None, retry_auth_errors=True, **kwds):
        """Make a request to the API and process the response.

        This method implements the low-level details of interacting with an
        FxA Web API, stripping away most of the details of HTTP.  It will
        return the parsed JSON of a successful responses, or raise an exception
        for an error response.  It's also responsible for backoff handling
        and clock-skew tracking.
        """
        # Don't make requests if we're in backoff.
        # Instead just synthesize a backoff response.
        if self._backoff_response is not None:
            if self._backoff_until >= self.client_curtime():
                resp = pickle.loads(self._backoff_response)
                resp.request = None
                resp.headers["Timestamp"] = str(int(self.server_curtime()))
                return resp
            else:
                self._backoff_until = 0
                self._backoff_response = None

        # Apply defaults and perform the request.
        while url.startswith("/"):
            url = url[1:]
        if not self.server_url.endswith("/"):
            self.server_url = self.server_url + "/"
        url = urljoin(self.server_url, url)
        if self.timeout is not None:
            kwds.setdefault("timeout", self.timeout)

        # Configure the user agent
        headers = kwds.get('headers', {})
        headers.setdefault('User-Agent', USER_AGENT_HEADER)
        kwds['headers'] = headers

        resp = self._session.request(method, url, json=json, **kwds)

        # Everything should return a valid JSON response.  Even errors.
        content_type = resp.headers.get("content-type", "")
        if not content_type.startswith("application/json"):
            msg = "API responded with non-json content-type: {0}"
            raise fxa.errors.OutOfProtocolError(msg.format(content_type))
        try:
            body = resp.json()
        except ValueError as e:
            msg = "API responded with invalid json: {0}"
            raise fxa.errors.OutOfProtocolError(msg.format(e))

        # Check for backoff indicator from the server.
        # If found, backoff up to the client-specified max time.
        if resp.status_code in (429, 500, 503):
            try:
                retry_after = int(resp.headers["retry-after"])
            except (KeyError, ValueError):
                pass
            else:
                if self.max_retry_after is not None:
                    retry_after = max(retry_after, self.max_retry_after)
                self._backoff_until = self.client_curtime() + retry_after
                self._backoff_response = pickle.dumps(resp)

        # If we get a 401 with "serverTime" field in the body, then we're
        # probably out of sync with the server's clock.  Check our skew,
        # adjust if necessary and try again.
        if retry_auth_errors:
            if resp.status_code == 401 and "serverTime" in body:
                try:
                    server_timestamp = int(body["serverTime"])
                except ValueError:
                    msg = "API responded with non-integer serverTime: {0}"
                    msg = msg.format(body["serverTime"])
                    raise fxa.errors.OutOfProtocolError(msg)
                # If our guestimate is more than 30 seconds out, try again.
                # This assumes the auth hook will use the updated clockskew.
                if abs(server_timestamp - self.server_curtime()) > 30:
                    self._clockskew = server_timestamp - self.client_curtime()
                    return self.request(method, url, json, False, **kwds)

        # See if we need to adjust for clock skew between client and server.
        # We do this automatically once per session in the hopes of avoiding
        # having to retry subsequent auth failures.  We do it *after* the retry
        # checking above, because it wrecks the "were we out of sync?" check.
        if self._clockskew is None and "timestamp" in resp.headers:
            try:
                server_timestamp = int(resp.headers["timestamp"])
            except ValueError:
                msg = "API responded with non-integer timestamp: {0}"
                msg = msg.format(resp.headers["timestamp"])
                raise fxa.errors.OutOfProtocolError(msg)
            else:
                self._clockskew = server_timestamp - self.client_curtime()

        # Raise exceptions for any error responses.
        # XXX TODO: hooks for raising error subclass based on errno.
        if 400 <= resp.status_code < 500:
            raise fxa.errors.ClientError(body)
        if 500 <= resp.status_code < 600:
            raise fxa.errors.ServerError(body)
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = "API responded with unexpected status code: {0}"
            raise fxa.errors.OutOfProtocolError(msg.format(resp.status_code))

        # Return the parsed JSON body for successful responses.
        return body

    def get(self, url, **kwds):
        return self.request("GET", url, **kwds)

    def post(self, url, json=None, **kwds):
        return self.request("POST", url, json, **kwds)

    def put(self, url, json=None, **kwds):
        return self.request("PUT", url, json, **kwds)

    def delete(self, url, **kwds):
        return self.request("DELETE", url, **kwds)


class HawkTokenAuth(requests.auth.AuthBase):
    """A requests auth hook implementing token-based hawk auth.

    This auth hook implements the hkdf-derived-hawk-token auth scheme
    as used by the Firefox Accounts auth server.  It uses HKDF to derive
    an id and secret key from a random 32-byte token, then signs the request
    with those credentials using the Hawk request-signing scheme.
    """

    def __init__(self, token, tokentype, apiclient=None):
        tokendata = unhexlify(token)
        key_material = fxa.crypto.derive_key(tokendata, tokentype, 3*32)
        self.id = hexstr(key_material[:32])
        self.auth_key = key_material[32:64]
        self.bundle_key = key_material[64:]
        self.apiclient = apiclient

    def __call__(self, req):
        # Requests doesn't include the port in the Host header by default.
        # Ensure a fully-correct value so that signatures work properly.
        req.headers["Host"] = urlparse(req.url).netloc
        params = {}
        if req.body:
            hasher = hashlib.sha256()
            hasher.update(b"hawk.1.payload\napplication/json\n")
            hasher.update(req.body.encode("utf8"))
            hasher.update(b"\n")
            hash = b64encode(hasher.digest())
            if PY3:
                hash = hash.decode("ascii")
            params["hash"] = hash
        if self.apiclient is not None:
            params["ts"] = str(int(self.apiclient.server_curtime()))
        hawkauthlib.sign_request(req, self.id, self.auth_key, params=params)
        return req

    def bundle(self, namespace, payload):
        """Bundle encrypted response data."""
        return fxa.crypto.bundle(self.bundle_key, namespace, payload)

    def unbundle(self, namespace, payload):
        """Unbundle encrypted response data."""
        return fxa.crypto.unbundle(self.bundle_key, namespace, payload)


class BearerTokenAuth(requests.auth.AuthBase):
    """A requests auth hook implementing OAuth bearer-token-based auth.

    This auth hook implements the simple "bearer token" auth scheme.
    The provided token is passed directly in the Authorization header.
    """

    def __init__(self, token, apiclient=None):
        self.token = token

    def __call__(self, req):
        req.headers["Authorization"] = "Bearer {0}".format(self.token)
        return req
