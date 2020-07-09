# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import json

import os
import base64
import hashlib
from six import string_types
from six.moves.urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import jwt
from fxa.cache import MemoryCache, DEFAULT_CACHE_EXPIRY
from fxa.constants import PRODUCTION_URLS
from fxa.errors import OutOfProtocolError, ScopeMismatchError, TrustError
from fxa._utils import APIClient, scope_matches, get_hmac


DEFAULT_SERVER_URL = PRODUCTION_URLS['oauth']
VERSION_SUFFIXES = ("/v1",)
TOKEN_HMAC_SECRET = 'PyFxA Token Cache Hmac Secret'


class Client(object):
    """Client for talking to the Firefox Accounts OAuth server"""

    def __init__(self, client_id=None, client_secret=None, server_url=None,
                 cache=True, ttl=DEFAULT_CACHE_EXPIRY, jwks=None):
        self.client_id = client_id
        self.client_secret = client_secret
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        server_url = server_url.rstrip('/')
        if not server_url.endswith(VERSION_SUFFIXES):
            server_url += VERSION_SUFFIXES[0]
        if isinstance(server_url, string_types):
            self.apiclient = APIClient(server_url)
        else:
            self.apiclient = server_url

        self.cache = cache
        if self.cache is True:
            self.cache = MemoryCache(ttl)

        if jwks is not None:
            # Fail early if bad JWKs were provided.
            for key in jwks:
                jwt.algorithms.RSAAlgorithm.from_jwk(key)
        self.jwks = jwks

    @property
    def server_url(self):
        return self.apiclient.server_url

    def _get_identity_assertion(self, sessionOrAssertion, client_id=None):
        if isinstance(sessionOrAssertion, string_types):
            return sessionOrAssertion
        if client_id is None:
            client_id = self.client_id
        return sessionOrAssertion.get_identity_assertion(
            audience=self.server_url,
            service=client_id
        )

    def get_client_metadata(self, client_id=None):
        """Get the OAuth client metadata for a given client_id."""
        if client_id is None:
            client_id = self.client_id
        return self.apiclient.get("/client/{0}".format(client_id))

    def get_redirect_url(self, state="", redirect_uri=None, scope=None,
                         action=None, email=None, client_id=None,
                         code_challenge=None, code_challenge_method=None,
                         access_type=None, keys_jwk=None):
        """Get the URL to redirect to to initiate the oauth flow."""
        if client_id is None:
            client_id = self.client_id
        params = {
            "client_id": client_id,
            "state": state,
        }
        if redirect_uri is not None:
            params["redirect_uri"] = redirect_uri
        if scope is not None:
            params["scope"] = scope
        if action is not None:
            params["action"] = action
        if email is not None:
            params["email"] = email
        if code_challenge is not None:
            params["code_challenge"] = code_challenge
        if code_challenge_method is not None:
            params["code_challenge_method"] = code_challenge_method
        if keys_jwk is not None:
            params["keys_jwk"] = keys_jwk
        if access_type is not None:
            params["access_type"] = access_type
        query_str = urlencode(params)
        authorization_url = urlparse(self.server_url + "/authorization")
        return urlunparse(authorization_url._replace(query=query_str))

    def trade_code(self, code, client_id=None, client_secret=None,
                   code_verifier=None, ttl=None):
        """Trade the authentication code for a longer lived token.

        :param code: the authentication code from the oauth redirect dance.
        :param client_id: the string generated during FxA client registration.
        :param client_secret: the related secret string.
        :param code_verifier: optional PKCE code verifier.
        :param ttl: optional ttl in seconds, the access token is valid for.
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
        }
        if client_secret is not None:
            body["client_secret"] = client_secret
        if code_verifier is not None:
            body["code_verifier"] = code_verifier
        if ttl is not None:
            body["ttl"] = ttl
        resp = self.apiclient.post(url, body)

        if 'access_token' not in resp:
            error_msg = 'access_token missing in OAuth response'
            raise OutOfProtocolError(error_msg)

        return resp

    def authorize_code(self, sessionOrAssertion, scope=None, client_id=None,
                       code_challenge=None, code_challenge_method=None):
        """Trade an identity assertion for an oauth authorization code.

        This method takes an identity assertion for a user and uses it to
        generate an oauth authentication code.  This code can in turn be
        traded for a full-blown oauth token.

        Note that the authorize_token() method does the same thing but skips
        the intermediate step of using a short-lived code.  You should prefer
        that method if the registered OAuth client_id has `canGrant` permission.

        :param sessionOrAssertion: an identity assertion for the target user,
                                   or an auth session to use to make one.
        :param scope: optional scope to be provided by the token.
        :param client_id: the string generated during FxA client registration.
        :param code_challenge: optional PKCE code challenge.
        """
        if client_id is None:
            client_id = self.client_id
        assertion = self._get_identity_assertion(sessionOrAssertion, client_id)
        url = "/authorization"

        # Although not relevant in this scenario from a security perspective,
        # we generate a random 'state' and check the returned redirect URL
        # for completeness.
        state = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')

        body = {
            "client_id": client_id,
            "assertion": assertion,
            "state": state
        }
        if scope is not None:
            body["scope"] = scope
        if code_challenge is not None:
            body["code_challenge"] = code_challenge
            body["code_challenge_method"] = code_challenge_method or "S256"
        resp = self.apiclient.post(url, body)

        if "redirect" not in resp:
            error_msg = "redirect missing in OAuth response"
            raise OutOfProtocolError(error_msg)

        # This flow is designed for web-based redirects.
        # In order to get the code we must parse it from the redirect url.
        query_params = parse_qs(urlparse(resp["redirect"]).query)

        # Check that the 'state' parameter is present and the same we provided
        if "state" not in query_params:
            error_msg = "state missing in OAuth response"
            raise OutOfProtocolError(error_msg)

        if state != query_params["state"][0]:
            error_msg = "state mismatch in OAuth response (wanted: '{}', got: '{}')".format(
                state, query_params["state"][0])
            raise OutOfProtocolError(error_msg)

        try:
            return query_params["code"][0]
        except (KeyError, IndexError, ValueError):
            error_msg = "code missing in OAuth redirect url"
            raise OutOfProtocolError(error_msg)

    def authorize_token(self, sessionOrAssertion, scope=None, client_id=None):
        """Trade an identity assertion for an oauth token.

        This method takes an identity assertion for a user and uses it to
        generate an oauth token. The client_id must have implicit grant
        privileges.

        :param sessionOrAssertion: an identity assertion for the target user,
                                   or an auth session to use to make one.
        :param scope: optional scope to be provided by the token.
        :param client_id: the string generated during FxA client registration.
        """
        if client_id is None:
            client_id = self.client_id
        assertion = self._get_identity_assertion(sessionOrAssertion, client_id)
        url = "/authorization"
        body = {
            "client_id": client_id,
            "assertion": assertion,
            "response_type": "token",
            "state": "x",  # state is required, but we don't use it
        }
        if scope is not None:
            body["scope"] = scope
        resp = self.apiclient.post(url, body)

        if 'access_token' not in resp:
            error_msg = 'access_token missing in OAuth response'
            raise OutOfProtocolError(error_msg)

        return resp['access_token']

    def _verify_jwt_token(self, key, token):
        pubkey = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        # The FxA OAuth ecosystem currently doesn't make good use of aud, and
        # instead relies on scope for restricting which services can accept
        # which tokens. So there's no value in checking it here, and in fact if
        # we check it here, it fails because the right audience isn't being
        # requested.
        decoded = jwt.decode(
            token, pubkey, algorithms=['RS256'], options={'verify_aud': False}
        )
        # Ref https://tools.ietf.org/html/rfc7515#section-4.1.9 the `typ` header
        # is lowercase and has an implicit default `application/` prefix.
        typ = jwt.get_unverified_header(token).get('typ', '')
        if '/' not in typ:
            typ = 'application/' + typ
        if typ.lower() != 'application/at+jwt':
            raise TrustError
        return {
            'user': decoded.get('sub'),
            'client_id': decoded.get('client_id'),
            'scope': decoded.get('scope', '').split(),
            'generation': decoded.get('fxa-generation'),
            'profile_changed_at': decoded.get('fxa-profileChangedAt')
        }

    def verify_token(self, token, scope=None):
        """Verify an OAuth token, and retrieve user id and scopes.

        :param token: the string to verify.
        :param scope: optional scope expected to be provided for this token.
        :returns: a dict with user id and authorized scopes for this token.
        :raises fxa.errors.ClientError: if the provided token is invalid.
        :raises fxa.errors.TrustError: if the token scopes do not match.
        """
        key = 'fxa.oauth.verify_token:%s:%s' % (
            get_hmac(token, TOKEN_HMAC_SECRET), scope)
        if self.cache is not None:
            resp = self.cache.get(key)
        else:
            resp = None

        if resp is None:
            # We want to fetch
            # https://oauth.accounts.firefox.com/.well-known/openid-configuration
            # and then get the jwks_uri key to get the /jwks url, but we'll
            # just hardcodes it like this for now; our /jwks url will never
            # change.
            # https://github.com/mozilla/PyFxA/issues/81 is an issue about
            # getting the jwks url out of the openid-configuration.
            keys = []
            if self.jwks is not None:
                keys.extend(self.jwks)
            else:
                keys.extend(self.apiclient.get('/jwks').get('keys', []))
            resp = None
            try:
                for k in keys:
                    try:
                        resp = self._verify_jwt_token(json.dumps(k), token)
                        break
                    except jwt.exceptions.InvalidSignatureError:
                        # It's only worth trying other keys in the event of
                        # `InvalidSignature`; if it was invalid for other reasons
                        # (e.g. it's expired) then using a different key won't
                        # help.
                        continue
                else:
                    # It's a well-formed JWT, but not signed by any of the advertized keys.
                    # We can immediately surface this as an error.
                    if len(keys) > 0:
                        raise TrustError({"error": "invalid signature"})
            except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidKeyError):
                # It wasn't a JWT at all, or it was signed using a key type we
                # don't support. Fall back to asking the FxA server to verify.
                pass
            except jwt.exceptions.PyJWTError as e:
                # Any other JWT-related failure (e.g. expired token) can
                # immediately surface as a trust error.
                raise TrustError({"error": str(e)})
            if resp is None:
                resp = self.apiclient.post('/verify', {'token': token})
            missing_attrs = ", ".join([
                k for k in ('user', 'scope', 'client_id')
                if resp.get(k) is None
            ])
            if missing_attrs:
                error_msg = '{0} missing in OAuth response'.format(
                    missing_attrs)
                raise OutOfProtocolError(error_msg)

            if scope is not None:
                authorized_scope = resp['scope']
                if not scope_matches(authorized_scope, scope):
                    raise ScopeMismatchError(authorized_scope, scope)

            if self.cache is not None:
                self.cache.set(key, json.dumps(resp))
        else:
            resp = json.loads(resp)

        return resp

    def destroy_token(self, token):
        """Destroy an OAuth token

        :param token: the token to destroy.
        :raises fxa.errors.ClientError: if the provided token is invalid.
        """
        url = '/destroy'
        body = {
            'token': token
        }
        self.apiclient.post(url, body)

    def generate_pkce_challenge(self):
        """Ramdomly generate parameters for a PKCE challenge.

        This method returns a two-tuple (challenge, response) where the first
        item contains request parameters for a PKCE challenge, and the second
        item contains the corresponding parameters for a verification.
        """
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip("=")
        raw_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(raw_challenge).decode('utf-8').rstrip("=")
        return ({
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }, {
            "code_verifier": code_verifier,
        })
