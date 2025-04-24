# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from binascii import unhexlify, hexlify
from secrets import token_bytes
from urllib.parse import quote as urlquote

from fxa.errors import ClientError
from fxa._utils import (
    APIClient,
    HawkTokenAuth,
    exactly_one_of,
    hexstr
)
from fxa.constants import PRODUCTION_URLS
from fxa.crypto import (
    create_salt,
    quick_stretch_password,
    stretch_password,
    unwrap_keys,
    derive_auth_pw,
    derive_wrap_kb,
)


DEFAULT_SERVER_URL = PRODUCTION_URLS['authentication']
VERSION_SUFFIXES = ("/v1",)

DEFAULT_ASSERTION_DURATION = 60
DEFAULT_CERT_DURATION = 1000 * 60 * 30  # half an hour, in milliseconds


class Client:
    """Client for talking to the Firefox Accounts auth server."""

    def __init__(self, server_url=None, key_stretch_version=1):
        if server_url is None:
            server_url = DEFAULT_SERVER_URL
        if not isinstance(server_url, str):
            self.apiclient = server_url
            self.server_url = self.apiclient.server_url
        else:
            server_url = server_url.rstrip("/")
            if not server_url.endswith(VERSION_SUFFIXES):
                server_url += VERSION_SUFFIXES[0]
            self.server_url = server_url
            self.apiclient = APIClient(server_url)

        if key_stretch_version not in [1, 2]:
            raise ValueError("Invalid key_stretch_version! Options are: 1,2")
        else:
            self.key_stretch_version = key_stretch_version

    def create_account(self, email, password=None, stretchpwd=None, **kwds):
        """creates an account with email and password.

        Note, the stretched password can also be provided. When doing this, and
        using key_stretch_version=2, the format changes from a string to StrechedPassword
        object
        """
        keys = kwds.pop("keys", False)

        if self.key_stretch_version == 2:
            spwd = StretchedPassword(2, email, create_salt(2, hexlify(token_bytes(16))),
                                     password, stretchpwd)
            kb = token_bytes(32)
            body = {
                "email": email,
                "authPW": spwd.get_auth_pw_v1(),
                "wrapKb": spwd.get_wrapkb_v1(kb),
                "authPWVersion2": spwd.get_auth_pw_v2(),
                "wrapKbVersion2": spwd.get_wrapkb_v2(kb),
                "clientSalt": spwd.v2_salt,
            }
        else:
            spwd = StretchedPassword(1, email, None, password, stretchpwd)
            body = {
                "email": email,
                "authPW": spwd.get_auth_pw_v1(),
            }

        EXTRA_KEYS = ("service", "redirectTo", "resume", "preVerifyToken",
                      "preVerified")
        for extra in kwds:
            if extra in EXTRA_KEYS:
                body[extra] = kwds[extra]
            else:
                msg = f"Unexpected keyword argument: {extra}"
                raise TypeError(msg)

        url = "/account/create"
        if keys:
            url += "?keys=true"

        resp = self.apiclient.post(url, body)

        if self.key_stretch_version == 2:
            stretchpwd_final = spwd
            key_fetch_token = resp.get('keyFetchTokenVersion2')
        else:
            stretchpwd_final = spwd.v1
            key_fetch_token = resp.get('keyFetchToken')

        # XXX TODO: somehow sanity-check the schema on this endpoint
        return Session(
            client=self,
            email=email,
            stretchpwd=stretchpwd_final,
            uid=resp["uid"],
            token=resp["sessionToken"],
            key_fetch_token=key_fetch_token,
            verified=False,
            auth_timestamp=resp["authAt"],
        )

    def login(self, email, password=None, stretchpwd=None, keys=False, unblock_code=None,
              verification_method=None, reason="login"):
        exactly_one_of(password, "password", stretchpwd, "stretchpwd")

        if self.key_stretch_version == 2:
            version, salt = self.get_key_stretch_version(email)
            salt = salt if version == 2 else create_salt(2, hexlify(token_bytes(16)))
            spwd = StretchedPassword(2, email, salt, password, stretchpwd)

            try:
                resp = self.start_password_change(email, spwd.v1)
                key_fetch_token = resp["keyFetchToken"]
                password_change_token = resp["passwordChangeToken"]
                kb = self.fetch_keys(resp["keyFetchToken"], spwd.v1)[1]
                resp = self.finish_password_change_v2(
                    password_change_token,
                    spwd,
                    kb
                )
                body = {
                    "email": email,
                    "authPW": spwd.get_auth_pw_v2(),
                    "reason": reason,
                }
            except Exception as inst:
                # If something goes wrong fallback to v1 logins!
                print("Warning! v2 key stretch auto upgrade failed! Falling back to v1 login. " +
                      f"Reason: {inst}")
                body = {
                    "email": email,
                    "authPW": spwd.get_auth_pw_v1(),
                    "reason": reason,
                }
        else:
            spwd = StretchedPassword(1, email, None, password, stretchpwd)
            body = {
                "email": email,
                "authPW": spwd.get_auth_pw_v1(),
                "reason": reason,
            }

        url = "/account/login"
        if keys:
            url += "?keys=true"
        if unblock_code:
            body["unblockCode"] = unblock_code
        if verification_method:
            body["verificationMethod"] = verification_method

        resp = self.apiclient.post(url, body)

        # Repackage stretchpwd based on version
        if self.key_stretch_version == 2:
            stretchpwd_final = spwd
            key_fetch_token = resp.get("keyFetchTokenVersion2")
        else:
            stretchpwd_final = spwd.v1
            key_fetch_token = resp.get("keyFetchToken")

        # XXX TODO: somehow sanity-check the schema on this endpoint
        return Session(
            client=self,
            email=email,
            stretchpwd=stretchpwd_final,
            uid=resp["uid"],
            token=resp["sessionToken"],
            key_fetch_token=key_fetch_token,
            verified=resp["verified"],
            verificationMethod=resp.get("verificationMethod"),
            auth_timestamp=resp["authAt"],
        )

    def _get_stretched_password(self, email, password=None, stretchpwd=None):
        if password is not None:
            if stretchpwd is not None:
                raise ValueError("must specify exactly one of 'password' or 'stretchpwd'")
            stretchpwd = quick_stretch_password(email, password)
        elif stretchpwd is None:
            raise ValueError("must specify one of 'password' or 'stretchpwd'")
        return stretchpwd

    def get_account_status(self, uid):
        return self.apiclient.get("/account/status?uid=" + uid)

    def destroy_account(self, email, password=None, stretchpwd=None):
        exactly_one_of(password, "password", stretchpwd, "stretchpwd")

        # create a session and get pack teh stretched password
        session = self.login(email, password, stretchpwd, keys=True)

        # grab the stretched pwd
        if isinstance(session.stretchpwd, bytes):
            stretchpwd = session.stretchpwd
        elif isinstance(session.stretchpwd, StretchedPassword) and session.stretchpwd.v2:
            stretchpwd = session.stretchpwd.v2
        elif isinstance(session.stretchpwd, StretchedPassword) and session.stretchpwd.v1:
            stretchpwd = session.stretchpwd.v1
        else:
            raise ValueError("Unknown session.stretchpwd state!")

        # destroy account
        url = "/account/destroy"
        body = {
            "email": email,
            "authPW": hexstr(derive_auth_pw(stretchpwd))
        }
        self.apiclient.post(url, body, auth=session._auth)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return unhexlify(self.apiclient.post("/get_random_bytes")["data"])

    def fetch_keys(self, key_fetch_token, stretchpwd):
        url = "/account/keys"
        auth = HawkTokenAuth(key_fetch_token, "keyFetchToken", self.apiclient)
        resp = self.apiclient.get(url, auth=auth)
        bundle = unhexlify(resp["bundle"])
        keys = auth.unbundle("account/keys", bundle)
        return unwrap_keys(keys, stretchpwd)

    def change_password(self, email, oldpwd=None, newpwd=None,
                        oldstretchpwd=None, newstretchpwd=None):
        exactly_one_of(oldpwd, "oldpwd", oldstretchpwd, "oldstretchpwd")
        exactly_one_of(newpwd, "newpwd", newstretchpwd, "newstretchpwd")

        if self.key_stretch_version == 2:
            version, salt = self.get_key_stretch_version(email)
            old_spwd = StretchedPassword(version, email, salt, oldpwd, oldstretchpwd)
            new_spwd = StretchedPassword(2, email, salt, newpwd, newstretchpwd)

            if version == 2:
                resp = self.start_password_change(email, old_spwd.v2)
                kb = self.fetch_keys(resp["keyFetchToken2"], old_spwd.v2)[1]
            else:
                resp = self.start_password_change(email, old_spwd.v1)["passwordChangeToken"]
                kb = self.fetch_keys(resp["keyFetchToken"], old_spwd.v1)[1]

            self.finish_password_change_v2(
                resp["passwordChangeToken"],
                new_spwd,
                kb)
        else:
            if oldpwd:
                oldstretchpwd = quick_stretch_password(email, oldpwd)
            if newpwd:
                newstretchpwd = quick_stretch_password(email, newpwd)
            resp = self.start_password_change(email, oldstretchpwd)
            kb = self.fetch_keys(resp["keyFetchToken"], oldstretchpwd)[1]
            new_wrapkb = derive_wrap_kb(kb, newstretchpwd)
            self.finish_password_change(resp["passwordChangeToken"], newstretchpwd, new_wrapkb)

    def start_password_change(self, email, stretchpwd):
        body = {
            "email": email,
            "oldAuthPW": hexstr(derive_auth_pw(stretchpwd)),
        }
        return self.apiclient.post("/password/change/start", body)

    def finish_password_change(self, token, stretchpwd, wrapkb):
        body = {
            "authPW": hexstr(derive_auth_pw(stretchpwd)),
            "wrapKb": hexstr(wrapkb),
        }
        auth = HawkTokenAuth(token, "passwordChangeToken", self.apiclient)
        self.apiclient.post("/password/change/finish", body, auth=auth)

    def finish_password_change_v2(self, token, spwd, kb):
        body = {
            "authPW": spwd.get_auth_pw_v1(),
            "wrapKb": spwd.get_wrapkb_v1(kb),
            "authPWVersion2": spwd.get_auth_pw_v2(),
            "wrapKbVersion2": spwd.get_wrapkb_v2(kb),
            "clientSalt": spwd.v2_salt,
        }
        auth = HawkTokenAuth(token, "passwordChangeToken", self.apiclient)

        return self.apiclient.post("/password/change/finish", body, auth=auth)

    def reset_account(self, email, token, password=None, stretchpwd=None):
        # TODO: Add support for recovery key!

        exactly_one_of(password, "password", stretchpwd, "stretchpwd")

        body = None
        if self.key_stretch_version == 2:
            version, salt = self.get_key_stretch_version(email)
            if version == 2:
                spwd = StretchedPassword(2, email, salt, password, stretchpwd)

                # Note, without recovery key, we must generate new kb
                kb = token_bytes(32)
                body = {
                    "email": email,
                    "authPW": spwd.get_auth_pw_v1(),
                    "wrapKb": spwd.get_wrapkb_v1(kb),
                    "authPWVersion2": spwd.get_auth_pw_v2(),
                    "wrapKbVersion2": spwd.get_wrapkb_v2(kb),
                    "clientSalt": salt,
                }

        if body is None:
            spwd = StretchedPassword(1, email, None, password, stretchpwd)
            body = {
                "authPW": spwd.get_auth_pw_v1(),
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
                msg = f"Unexpected keyword argument: {extra}"
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
                msg = f"Unexpected keyword argument: {extra}"
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

    def verify_email_code(self, uid, code):
        body = {
            "uid": uid,
            "code": code,
        }
        url = "/recovery_email/verify_code"
        return self.apiclient.post(url, body)

    def send_unblock_code(self, email, **kwds):
        body = {
            "email": email
        }

        url = "/account/login/send_unblock_code"
        return self.apiclient.post(url, body)

    def reject_unblock_code(self, uid, unblockCode):
        body = {
            "uid": uid,
            "unblockCode": unblockCode
        }
        url = "/account/login/reject_unblock_code"
        return self.apiclient.post(url, body)

    def get_key_stretch_version(self, email):
        # Fall back to v1 stretching if an error occurs here, which happens when
        # the account does not exist at all.
        try:
            body = {
                "email": email
            }
            resp = self.apiclient.post("/account/credentials/status", body)
        except ClientError:
            return 1, email

        version = resp["currentVersion"]
        if version == "v1":
            return 1, create_salt(1, email)
        if version == "v2":
            return 2, resp["clientSalt"]

        raise ValueError("Unknown version provided by api! Aborting...")


class Session:

    def __init__(self, client, email, stretchpwd, uid, token,
                 key_fetch_token=None, verified=False, verificationMethod=None,
                 auth_timestamp=0, cert_keypair=None):
        self.client = client
        self.email = email
        self.uid = uid
        self.token = token
        self.verified = verified
        self.verificationMethod = verificationMethod
        self.auth_timestamp = auth_timestamp
        self.cert_keypair = None
        self.keys = None
        self._auth = HawkTokenAuth(token, "sessionToken", self.apiclient)
        self._key_fetch_token = key_fetch_token

        # Quick validation on stretchpwd
        if not isinstance(stretchpwd, StretchedPassword) and not isinstance(stretchpwd, bytes):
            raise ValueError("stretchpwd must be a bytes or a StretchedPassword instance, " +
                             f"but was {stretchpwd}")
        self.stretchpwd = stretchpwd

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
            if isinstance(self.stretchpwd, StretchedPassword):
                stretchpwd = self.stretchpwd.v2
            else:
                stretchpwd = self.stretchpwd
        elif isinstance(stretchpwd, StretchedPassword):
            stretchpwd = stretchpwd.v2

        if stretchpwd is None:
            # XXX TODO: what error?
            raise RuntimeError("missing stretchpwd")
        self.keys = self.client.fetch_keys(key_fetch_token, stretchpwd)
        self._key_fetch_token = None
        self.stretchpwd = None
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
        return self.client.verify_email_code(self.uid, code)  # note: not authenticated

    def resend_email_code(self, **kwds):
        body = {}
        for extra in kwds:
            if extra in ("service", "redirectTo", "resume"):
                body[extra] = kwds[extra]
            else:
                msg = f"Unexpected keyword argument: {extra}"
                raise TypeError(msg)
        url = "/recovery_email/resend_code"
        self.apiclient.post(url, body, auth=self._auth)

    def totp_create(self):
        url = "/totp/create"
        return self.apiclient.post(url, {}, auth=self._auth)

    def totp_exists(self):
        url = "/totp/exists"
        resp = self.apiclient.get(url, auth=self._auth)
        return resp["exists"]

    def totp_delete(self):
        url = "/totp/destroy"
        return self.apiclient.post(url, {}, auth=self._auth)

    def totp_verify(self, code):
        url = "/session/verify/totp"
        body = {
            "code": code,
        }
        resp = self.apiclient.post(url, body, auth=self._auth)
        if resp["success"]:
            self.verified = True

        return resp["success"]

    def sign_certificate(self, public_key, duration=DEFAULT_CERT_DURATION,
                         service=None):
        body = {
            "publicKey": public_key,
            "duration": duration,
        }
        url = "/certificate/sign"
        if service is not None:
            url += "?service=" + urlquote(service)
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


class PasswordForgotToken:

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


class StretchedPassword:

    def __init__(self, version, email, salt=None, password=None, stretchpwd=None):
        self.version = version

        if version == 2:
            if not salt:
                salt = create_salt(2, hexlify(token_bytes(16)))

            if stretchpwd and not isinstance(stretchpwd, StretchedPassword):
                raise ValueError("invalid stretchpwd type")

            if stretchpwd:
                if not isinstance(stretchpwd, StretchedPassword):
                    raise ValueError(f"invalid stretchpwd type: {type(stretchpwd)}")

                self.v1 = stretchpwd.v1
                self.v2_salt = stretchpwd.v2_salt
                self.v2 = stretchpwd.v2
            else:
                if not isinstance(password, str):
                    raise ValueError(f"invalid password type: {type(stretchpwd)}")
                self.v1 = quick_stretch_password(email, password)
                self.v2_salt = salt
                self.v2 = stretch_password(self.v2_salt, password)
        else:
            if stretchpwd:
                if not isinstance(stretchpwd, bytes):
                    raise ValueError(f"invalid stretchpwd type: {type(stretchpwd)}")
                self.v1 = stretchpwd
            else:
                if not isinstance(password, str):
                    raise ValueError(f"invalid password type: {type(password)}")
                self.v1 = quick_stretch_password(email, password)

    def get_auth_pw(self):
        if self.v2:
            return self.get_auth_pw_v2()
        elif self.v1:
            return self.get_auth_pw_v1()
        else:
            return None

    def get_auth_pw_v1(self):
        return hexstr(derive_auth_pw(self.v1))

    def get_auth_pw_v2(self):
        return hexstr(derive_auth_pw(self.v2))

    def get_wrapkb_v1(self, kb):
        return hexstr(derive_wrap_kb(kb, self.v1))

    def get_wrapkb_v2(self, kb):
        return hexstr(derive_wrap_kb(kb, self.v2))
