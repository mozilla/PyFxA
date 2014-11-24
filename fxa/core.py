# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from binascii import hexlify, unhexlify

from fxa._utils import APIClient, HawkTokenAuth
from fxa.crypto import quick_stretch_password, derive_key, xor


DEFAULT_SERVER_URL = "https://api.accounts.firefox.com"

DEFAULT_CERT_DURATION = 1000 * 60 * 30  # half an hour, in milliseconds


class Client(object):
    """Client for talking to the Firefox Accounts auth server."""

    def __init__(self, server_url=None, apiclient=None):
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        self.server_url = server_url
        if apiclient is None:
            apiclient = APIClient(self.server_url)
        self.apiclient = apiclient

    def create_account(self, email, password=None, stretchpwd=None, **kwds):
        keys = kwds.pop("keys", False)
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": hexlify(derive_key(stretchpwd, "authPW")),
        }
        EXTRA_KEYS = ("service", "redirectTo", "resume", "preVerifyToken",
                      "preVerified")
        for extra in kwds:
            if extra in EXTRA_KEYS:
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/v1/account/create"
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
            "authPW": hexlify(derive_key(stretchpwd, "authPW")),
        }
        url = "/v1/account/login"
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
        return self.apiclient.get("/v1/account/status?uid=" + uid)

    def destroy_account(self, email, password=None, stretchpwd=None):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "email": email,
            "authPW": hexlify(derive_key(stretchpwd, "authPW")),
        }
        url = "/v1/account/destroy"
        self.apiclient.post(url, body)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return unhexlify(self.apiclient.post("/v1/get_random_bytes")["data"])

    def reset_account(self, email, token, password=None, stretchpwd=None):
        stretchpwd = self._get_stretched_password(email, password, stretchpwd)
        body = {
            "authPW": hexlify(derive_key(stretchpwd, "authPW")),
        }
        url = "/v1/account/reset"
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
        url = "/v1/password/forgot/send_code"
        return self.apiclient.post(url, body)

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
        url = "/v1/password/forgot/resend_code"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

    def verify_reset_code(self, token, code):
        body = {
            "code": code,
        }
        url = "/v1/password/forgot/verify_code"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

    def get_reset_code_status(self, token):
        url = "/v1/password/forgot/status"
        auth = HawkTokenAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.get(url, auth=auth)


class Session(object):

    def __init__(self, client, email, stretchpwd, uid, token,
                 key_fetch_token=None, verified=False, auth_timestamp=0):
        self.client = client
        self.email = email
        self.uid = uid
        self.token = token
        self.verified = verified
        self.auth_timestamp = auth_timestamp
        self.keys = None
        self._auth = HawkTokenAuth(token, "sessionToken", self.apiclient)
        self._key_fetch_token = key_fetch_token
        self._stretchpwd = stretchpwd

    @property
    def apiclient(self):
        return self.client.apiclient

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
        # Fetch the keys, and clear cached values from session construction.
        url = "/v1/account/keys"
        auth = HawkTokenAuth(key_fetch_token, "keyFetchToken", self.apiclient)
        resp = self.apiclient.get(url, auth=auth)
        self._key_fetch_token = None
        self._stretchpwd = None
        # Decrypt kB using the stretchpwd.
        bundle = unhexlify(resp["bundle"])
        keys = auth.unbundle("account/keys", bundle)
        unwrap_key = derive_key(stretchpwd, "unwrapBkey")
        self.keys = (keys[:32], xor(keys[32:], unwrap_key))
        return self.keys

    def check_session_status(self):
        url = "/v1/session/status"
        # Raises an error if the session has expired etc.
        try:
            uid = self.apiclient.get(url, auth=self._auth)["uid"]
        except KeyError:
            pass
        else:
            # XXX TODO: what error?
            assert uid == self.uid

    def destroy_session(self):
        url = "/v1/session/destroy"
        self.apiclient.post(url, {}, auth=self._auth)

    def get_email_status(self):
        url = "/v1/recovery_email/status"
        resp = self.apiclient.get(url, auth=self._auth)
        self.verified = resp["verified"]
        return resp

    def verify_email_code(self, code):
        body = {
            "uid": self.uid,
            "code": code,
        }
        url = "/v1/recovery_email/verify_code"
        self.apiclient.post(url, body)  # note: not authenticated

    def resend_email_code(self, **kwds):
        body = {}
        for extra in kwds:
            if extra in ("service", "redirectTo", "resume"):
                body[extra] = kwds[extra]
            else:
                msg = "Unexpected keyword argument: {0}".format(extra)
                raise TypeError(msg)
        url = "/v1/recovery_email/resend_code"
        self.apiclient.get(url, body, auth=self._auth)

    def sign_certificate(self, public_key, duration=DEFAULT_CERT_DURATION):
        body = {
            "publicKey": public_key,
            "duration": duration,
        }
        url = "/v1/certificate/sign"
        resp = self.apiclient.post(url, body, auth=self._auth)
        return resp["cert"]

    def change_password(self, oldpwd, newpwd):
        stretched_oldpwd = quick_stretch_password(self.email, oldpwd)
        resp = self.start_password_change(stretched_oldpwd)
        keys = self.fetch_keys(resp["keyFetchToken"], stretched_oldpwd)
        token = resp["passwordChangeToken"]
        stretched_newpwd = quick_stretch_password(self.email, newpwd)
        new_wrapkb = xor(keys[1], derive_key(stretched_newpwd, "unwrapBkey"))
        self.finish_password_change(token, stretched_newpwd, new_wrapkb)

    def start_password_change(self, stretchpwd):
        body = {
            "email": self.email,
            "oldAuthPW": hexlify(derive_key(stretchpwd, "authPW")),
        }
        return self.apiclient.post("/v1/password/change/start", body)

    def finish_password_change(self, token, stretchpwd, wrapkb):
        body = {
            "authPW": hexlify(derive_key(stretchpwd, "authPW")),
            "wrapKb": hexlify(wrapkb),
        }
        auth = HawkTokenAuth(token, "passwordChangeToken", self.apiclient)
        self.apiclient.post("/v1/password/change/finish", body, auth=auth)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return self.client.get_random_bytes()
