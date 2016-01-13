# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from binascii import unhexlify

from six import string_types

import browserid.jwt
import browserid.utils

from fxa._utils import hexstr, APIClient, HawkTokenAuth
from fxa.constants import PRODUCTION_URLS
from fxa.crypto import (
    quick_stretch_password,
    generate_keypair,
    derive_key,
    xor
)


DEFAULT_SERVER_URL = PRODUCTION_URLS['authentication']
VERSION_SUFFIXES = ("/v1",)

DEFAULT_ASSERTION_DURATION = 60
DEFAULT_CERT_DURATION = 1000 * 60 * 30  # half an hour, in milliseconds


class Client(object):
    """Client for talking to the Firefox Accounts auth server."""

    def __init__(self, server_url=None):
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        if not isinstance(server_url, string_types):
            self.apiclient = server_url
            self.server_url = self.apiclient.server_url
        else:
            server_url = server_url.rstrip("/")
            if not server_url.endswith(VERSION_SUFFIXES):
                server_url += VERSION_SUFFIXES[0]
            self.server_url = server_url
            self.apiclient = APIClient(server_url)

    def create_account(self, email, password=None, stretchpwd=None, **kwds):
        keys = kwds.pop("keys", False)
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": hexstr(derive_key(stretchpwd, "authPW")),
        }
        EXTRA_KEYS = ("service", "redirectTo", "resume", "preVerifyToken",
                      "preVerified")
        for extra in kwds:
            if extra in EXTRA_KEYS:
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/account/create"
        if keys:
            url += "?keys=true"
        resp = self.apiclient.post(url, body)
        # XXX TODO: somehow sanity-check the schema on this endpoint
        return Session(
            client=self,
            email=email,
            stretchpwd=stretchpwd,
            uid=resp["uid"],
            token=resp["sessionToken"],
            key_fetch_token=resp.get("keyFetchToken"),
            verified=False,
            auth_timestamp=resp["authAt"],
        )

    def login(self, email, password=None, stretchpwd=None, keys=False):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": hexstr(derive_key(stretchpwd, "authPW")),
        }
        url = "/account/login"
        if keys:
            url += "?keys=true"
        resp = self.apiclient.post(url, body)
        # XXX TODO: somehow sanity-check the schema on this endpoint
        return Session(
            client=self,
            email=email,
            stretchpwd=stretchpwd,
            uid=resp["uid"],
            token=resp["sessionToken"],
            key_fetch_token=resp.get("keyFetchToken"),
            verified=resp["verified"],
            auth_timestamp=resp["authAt"],
        )

    def _get_stretched_password(self, email, password=None, stretchpwd=None):
        if password is not None:
            if stretchpwd is not None:
                msg = "must specify exactly one of 'password' or 'stretchpwd'"
                raise ValueError(msg)
            stretchpwd = quick_stretch_password(email, password)
        elif stretchpwd is None:
            raise ValueError("must specify one of 'password' or 'stretchpwd'")
        return stretchpwd

    def get_account_status(self, uid):
        return self.apiclient.get("/account/status?uid=" + uid)

    def destroy_account(self, email, password=None, stretchpwd=None):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": hexstr(derive_key(stretchpwd, "authPW")),
        }
        url = "/account/destroy"
        self.apiclient.post(url, body)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return unhexlify(self.apiclient.post("/get_random_bytes")["data"])

    def fetch_keys(self, key_fetch_token, stretchpwd):
        url = "/account/keys"
        auth = HawkTokenAuth(key_fetch_token, "keyFetchToken", self.apiclient)
        resp = self.apiclient.get(url, auth=auth)
        bundle = unhexlify(resp["bundle"])
        keys = auth.unbundle("account/keys", bundle)
        unwrap_key = derive_key(stretchpwd, "unwrapBkey")
        return (keys[:32], xor(keys[32:], unwrap_key))

    def change_password(self, email, oldpwd=None, newpwd=None,
                        oldstretchpwd=None, newstretchpwd=None):
        oldstretchpwd = self._get_stretched_password(email, oldpwd,
                                                     oldstretchpwd)
        newstretchpwd = self._get_stretched_password(email, newpwd,
                                                     newstretchpwd)
        resp = self.start_password_change(email, oldstretchpwd)
        keys = self.fetch_keys(resp["keyFetchToken"], oldstretchpwd)
        token = resp["passwordChangeToken"]
        new_wrapkb = xor(keys[1], derive_key(newstretchpwd, "unwrapBkey"))
        self.finish_password_change(token, newstretchpwd, new_wrapkb)

    def start_password_change(self, email, stretchpwd):
        body = {
            "email": email,
            "oldAuthPW": hexstr(derive_key(stretchpwd, "authPW")),
        }
        return self.apiclient.post("/password/change/start", body)

    def finish_password_change(self, token, stretchpwd, wrapkb):
        body = {
            "authPW": hexstr(derive_key(stretchpwd, "authPW")),
            "wrapKb": hexstr(wrapkb),
        }
        auth = HawkTokenAuth(token, "passwordChangeToken", self.apiclient)
        self.apiclient.post("/password/change/finish", body, auth=auth)

    def reset_account(self, email, token, password=None, stretchpwd=None):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "authPW": hexstr(derive_key(stretchpwd, "authPW")),
        }
        url = "/account/reset"
        auth = HawkTokenAuth(token, "accountResetToken", self.apiclient)
        self.apiclient.post(url, body, auth=auth)

    def send_reset_code(self, email, **kwds):
        body = {
            "email": email,
        }
        for extra in kwds:
            if extra in ("service", "redirectTo", "resume"):
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/password/forgot/send_code"
        resp = self.apiclient.post(url, body)
        return PasswordForgotToken(
            self, email,
            resp["passwordForgotToken"],
            resp["ttl"],
            resp["codeLength"],
            resp["tries"],
        )

    def resend_reset_code(self, email, token, **kwds):
        body = {
            "email": email,
        }
        for extra in kwds:
            if extra in ("service", "redirectTo", "resume"):
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/password/forgot/resend_code"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

    def verify_reset_code(self, token, code):
        body = {
            "code": code,
        }
        url = "/password/forgot/verify_code"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

    def get_reset_code_status(self, token):
        url = "/password/forgot/status"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.get(url, auth=auth)


class Session(object):

    def __init__(self, client, email, stretchpwd, uid, token,
                 key_fetch_token=None, verified=False, auth_timestamp=0,
                 cert_keypair=None):
        self.client = client
        self.email = email
        self.uid = uid
        self.token = token
        self.verified = verified
        self.auth_timestamp = auth_timestamp
        self.cert_keypair = None
        self.keys = None
        self._auth = HawkTokenAuth(token, "sessionToken", self.apiclient)
        self._key_fetch_token = key_fetch_token
        self._stretchpwd = stretchpwd

    @property
    def apiclient(self):
        return self.client.apiclient

    @property
    def server_url(self):
        return self.client.server_url

    def fetch_keys(self, key_fetch_token=None, stretchpwd=None):
        # Use values from session construction, if not overridden.
        if key_fetch_token is None:
            key_fetch_token = self._key_fetch_token
            if key_fetch_token is None:
                # XXX TODO: what error?
                raise RuntimeError("missing key_fetch_token")
        if stretchpwd is None:
            stretchpwd = self._stretchpwd
            if stretchpwd is None:
                # XXX TODO: what error?
                raise RuntimeError("missing stretchpwd")
        self.keys = self.client.fetch_keys(key_fetch_token, stretchpwd)
        self._key_fetch_token = None
        self._stretchpwd = None
        return self.keys

    def check_session_status(self):
        url = "/session/status"
        # Raises an error if the session has expired etc.
        try:
            uid = self.apiclient.get(url, auth=self._auth)["uid"]
        except KeyError:
            pass
        else:
            # XXX TODO: what error?
            assert uid == self.uid

    def destroy_session(self):
        url = "/session/destroy"
        self.apiclient.post(url, {}, auth=self._auth)

    def get_email_status(self):
        url = "/recovery_email/status"
        resp = self.apiclient.get(url, auth=self._auth)
        self.verified = resp["verified"]
        return resp

    def verify_email_code(self, code):
        body = {
            "uid": self.uid,
            "code": code,
        }
        url = "/recovery_email/verify_code"
        self.apiclient.post(url, body)  # note: not authenticated

    def resend_email_code(self, **kwds):
        body = {}
        for extra in kwds:
            if extra in ("service", "redirectTo", "resume"):
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/recovery_email/resend_code"
        self.apiclient.post(url, body, auth=self._auth)

    def sign_certificate(self, public_key, duration=DEFAULT_CERT_DURATION):
        body = {
            "publicKey": public_key,
            "duration": duration,
        }
        url = "/certificate/sign"
        resp = self.apiclient.post(url, body, auth=self._auth)
        return resp["cert"]

    def change_password(self, oldpwd, newpwd,
                        oldstretchpwd=None, newstretchpwd=None):
        return self.client.change_password(self.email, oldpwd, newpwd,
                                           oldstretchpwd, newstretchpwd)

    def start_password_change(self, stretchpwd):
        return self.client.start_password_change(self.email, stretchpwd)

    def finish_password_change(self, token, stretchpwd, wrapkb):
        return self.client.finish_password_change(token, stretchpwd, wrapkb)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return self.client.get_random_bytes()

    def get_identity_assertion(self, audience,
                               duration=DEFAULT_ASSERTION_DURATION,
                               exp=None,
                               keypair=None):
        if exp is None:
            exp = int((self.apiclient.server_curtime() + duration) * 1000)
        if keypair is None:
            keypair = self.cert_keypair
            if keypair is None:
                keypair = generate_keypair()
                self.cert_keypair = keypair
        public_key, private_key = keypair
        # Get a signed identity certificate for the public key.
        # XXX TODO: cache this for future re-use?
        # For now we just get a fresh signature every time, which is
        # perfectly valid but costly if done frequently.
        cert = self.sign_certificate(public_key, duration=duration*1000)
        # Generate assertion using the private key.
        assertion = {
            "exp": exp,
            "aud": audience,
        }
        assertion = browserid.jwt.generate(assertion, private_key)
        # Bundle them into a full BrowserID assertion.
        return browserid.utils.bundle_certs_and_assertion([cert], assertion)


class PasswordForgotToken(object):

    def __init__(self, client, email, token, ttl=0, code_length=16,
                 tries_remaining=1):
        self.client = client
        self.email = email
        self.token = token
        self.ttl = ttl
        self.code_length = code_length
        self.tries_remaining = tries_remaining

    def verify_code(self, code):
        resp = self.client.verify_reset_code(self.token, code)
        return resp["accountResetToken"]

    def resend_code(self, **kwds):
        resp = self.client.resend_reset_code(self.email, self.token, **kwds)
        self.ttl = resp["ttl"]
        self.code_length = resp["codeLength"]
        self.tries_remaining = resp["tries"]

    def get_status(self):
        resp = self.client.get_reset_code_status(self.token)
        self.ttl = resp["ttl"]
        self.tries_remaining = resp["tries"]
        return resp
