# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

fxa._utils:  miscellaneous low-level utilities for PyFxA

This private-api stuff that will most likely change, move, refactor
etc as we go.  So don't import any of it outside of this package.

"""
import os
import time
import hashlib
import hmac
import warnings
from binascii import hexlify, unhexlify
try:
    import cPickle as pickle
except ImportError:  # pragma: no cover
    import pickle

from urllib.parse import urljoin, urlparse

import requests
import requests.auth
import requests.utils
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

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


# Typed Bearer-token prefix per FxA token kind. Must stay in sync with the
# auth-server table in `lib/routes/auth-schemes/bearer-fxa-token.js` and the
# auth-client `lib/bearer.ts`. The prefix keeps these tokens disjoint from the
# OAuth refresh-token scheme (plain `Bearer <hex>`) and from legacy Hawk on
# routes that accept more than one. See ADR-0022 / ADR-0050 and
# https://mozilla.github.io/ecosystem-platform/reference/authentication-schemes
TOKEN_PREFIXES = {
    "sessionToken": "fxs",
    "keyFetchToken": "fxk",
    "accountResetToken": "fxar",
    "passwordForgotToken": "fxpf",
    "passwordChangeToken": "fxpc",
}


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

        The rules for parsing and matching scopes in FxA are documented at
        https://github.com/mozilla/fxa-oauth-server/blob/master/docs/scopes.md

    :param provided: list of scopes provided for the current token.
    :param required: the scope required (e.g. by the application).
    :returns: ``True`` if all required scopes are provided, ``False`` if not.
    """
    if isinstance(provided, str):
        raise ValueError("Provided scopes must be a list, not a single string")

    if not isinstance(required, (list, tuple)):
        required = [required]

    for req in required:
        if not any(_match_single_scope(prov, req) for prov in provided):
            return False

    return True


def _match_single_scope(provided, required):
    if provided.startswith('https:'):
        return _match_url_scope(provided, required)
    else:
        return _match_shortname_scope(provided, required)


def _match_shortname_scope(provided, required):
    if required.startswith('https:'):
        return False
    prov_names = provided.split(':')
    req_names = required.split(':')
    # If we require :write, it must be provided.
    if req_names[-1] == 'write':
        if prov_names[-1] != 'write':
            return False
        req_names.pop()
        prov_names.pop()
    elif prov_names[-1] == 'write':
        prov_names.pop()
    # Provided names must be a prefix of required names.
    if len(prov_names) > len(req_names):
        return False
    for (p, r) in zip(prov_names, req_names):
        if p != r:
            return False
    # It matches!
    return True


def _match_url_scope(provided, required):
    if not required.startswith('https:'):
        return False
    # Pop the hash fragments
    (prov_url, prov_hash) = (provided.rsplit('#', 1) + [None])[:2]
    (req_url, req_hash) = (required.rsplit('#', 1) + [None])[:2]
    # Provided URL must be a prefix of required.
    if req_url != prov_url:
        if not (req_url.startswith(prov_url + '/')):
            return False
    # If hash is provided, it must match that required.
    if prov_hash:
        if not req_hash or req_hash != prov_hash:
            return False
    # It matches!
    return True


class APIClient:
    """A requests.Session wrapper specialized for FxA API access.

    An instance of this class should be used for making requests to an FxA
    web API endpoint.  It wraps a requests.Session instance and provides
    a broadly similar interface, with some additional functionality that's
    specific to Firefox Accounts:

        * default base server URL
        * backoff protocol support
        * sensible request timeouts
        * CI WAF bypass header injection

    """

    def __init__(self, server_url, session=None):
        if session is None:
            session = requests.Session()
            # Mount an HTTPAdapter to retry requests.
            retries = Retry(
                total=3,
                backoff_factor=0.5,
                allowed_methods={"DELETE", "GET", "POST", "PUT"},
            )
            session.mount(server_url, HTTPAdapter(max_retries=retries))
        waf_token = os.environ.get("CI_WAF_TOKEN")
        if waf_token:
            session.headers["fxa-ci"] = waf_token
        # Properties that can be customized to change behaviour.
        self.server_url = server_url
        self.timeout = 30
        self.max_retry_after = None
        # Internal state.
        self._session = session
        self._backoff_until = 0
        self._backoff_response = None

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
        It's mostly here to assist in testability of this class.
        """
        return time.time()

    # The actual request-making stuff.

    def request(self, method, url, json=None, **kwds):
        """Make a request to the API and process the response.

        This method implements the low-level details of interacting with an
        FxA Web API, stripping away most of the details of HTTP.  It will
        return the parsed JSON of a successful responses, or raise an exception
        for an error response.  It's also responsible for backoff handling.
        """
        # Don't make requests if we're in backoff.
        # Instead just synthesize a backoff response.
        if self._backoff_response is not None:
            if self._backoff_until >= self.client_curtime():
                resp = pickle.loads(self._backoff_response)
                resp.request = None
                return resp
            else:
                self._backoff_until = 0
                self._backoff_response = None

        # Apply defaults and perform the request.
        while url.startswith("/"):
            url = url[1:]
        if self.server_url.endswith("/"):
            url = urljoin(self.server_url, url)
        else:
            url = urljoin(self.server_url + "/", url)
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


_LOOPBACK_HOSTS = frozenset(("localhost", "127.0.0.1", "0.0.0.0", "::1"))


def _reject_insecure_token_transport(url):
    """Refuse to send a bearer credential over plaintext HTTP.

    Unlike the old Hawk signature, the Bearer header is a replayable
    credential, so its confidentiality depends entirely on TLS. Loopback hosts
    are exempt so local development against an http auth-server still works.
    """
    parsed = urlparse(url)
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
        raise fxa.errors.TrustError(
            "Refusing to send an FxA token over a non-HTTPS connection to "
            f"{parsed.hostname}: the Bearer header is a replayable credential "
            "and must only be sent over https."
        )


class FxATokenBearerAuth(requests.auth.AuthBase):
    """A requests auth hook for FxA tokens delivered as prefixed Bearer tokens.

    This auth hook implements the prefixed-Bearer scheme that replaced Hawk on
    the Firefox Accounts auth server (ADR-0022).  It uses HKDF to derive an id
    and bundle key from a random 32-byte token, then sends the id in the
    Authorization header as ``Bearer <prefix>_<id>``, where ``<prefix>``
    identifies the token kind (see ``TOKEN_PREFIXES``).

    The HKDF derivation is scheme-neutral: the same id is what the legacy Hawk
    strategy looked up server-side, and the bundle key is still used to
    unbundle encrypted ``account/keys`` responses.
    """

    def __init__(self, token, tokentype, apiclient=None):
        try:
            self.prefix = TOKEN_PREFIXES[tokentype]
        except KeyError:
            raise ValueError(f"unknown token kind: {tokentype!r}") from None
        tokendata = unhexlify(token)
        # 96 bytes keeps id ([:32]) and bundle_key ([64:]) at server offsets;
        # the middle 32 (old Hawk auth key) are unused.
        key_material = fxa.crypto.derive_key(tokendata, tokentype, 3*32)
        self.id = hexstr(key_material[:32])
        self.bundle_key = key_material[64:]
        # Unused by the Bearer scheme (Hawk read it for the request timestamp);
        # retained for signature back-compat with callers and the auth setter.
        self.apiclient = apiclient

    def __call__(self, req):
        _reject_insecure_token_transport(req.url)
        req.headers["Authorization"] = f"Bearer {self.prefix}_{self.id}"
        return req

    def bundle(self, namespace, payload):
        """Bundle encrypted response data."""
        return fxa.crypto.bundle(self.bundle_key, namespace, payload)

    def unbundle(self, namespace, payload):
        """Unbundle encrypted response data."""
        return fxa.crypto.unbundle(self.bundle_key, namespace, payload)


class HawkTokenAuth(FxATokenBearerAuth):
    """Deprecated alias for :class:`FxATokenBearerAuth`.

    Hawk signing was removed in the Bearer migration (ADR-0022); this name now
    emits a prefixed Bearer header. Kept so existing imports keep working, but
    it warns so callers know to switch to ``FxATokenBearerAuth``.
    """

    def __init__(self, *args, **kwds):
        warnings.warn(
            "HawkTokenAuth is deprecated and no longer uses Hawk; "
            "use FxATokenBearerAuth instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwds)


class BearerTokenAuth(requests.auth.AuthBase):
    """A requests auth hook implementing OAuth bearer-token-based auth.

    This auth hook implements the simple "bearer token" auth scheme.
    The provided token is passed directly in the Authorization header.
    """

    def __init__(self, token, apiclient=None):
        self.token = token

    def __call__(self, req):
        req.headers["Authorization"] = f"Bearer {self.token}"
        return req


def _decoded(value, encoding='utf-8'):
    """Make sure the value is of type ``unicode`` in both PY2 and PY3."""
    if not isinstance(value, str):
        value = value.decode(encoding)
    return value


def exactly_one_of(p1_val, p1_name, p2_val, p2_name):
    if p1_val and p2_val or not p1_val and not p2_val:
        raise ValueError(f"must specify exactly one of '{p1_name}' or '{p2_name}'")
