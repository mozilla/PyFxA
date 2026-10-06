# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from binascii import unhexlify, hexlify
from secrets import token_bytes

from fxa.errors import ClientError
from fxa._utils import (
    APIClient,
    BearerTokenAuth,
    FxATokenBearerAuth,
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

        EXTRA_KEYS = ("service", "redirectTo", "resume")
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

        upgrade = False
        if self.key_stretch_version == 2:
            version, salt = self.get_key_stretch_version(email)
            upgrade = version != 2
            salt = salt if not upgrade else create_salt(2, hexlify(token_bytes(16)))
            spwd = StretchedPassword(2, email, salt, password, stretchpwd)
            # A v1 account signs in with v1 credentials, then upgrades below.
            body = {
                "email": email,
                "authPW": spwd.get_auth_pw_v1() if upgrade else spwd.get_auth_pw_v2(),
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
        if upgrade:
            try:
                change = self.start_password_change(email, spwd.v1, resp["sessionToken"])
                kb = self.fetch_keys(change["keyFetchToken"], spwd.v1)[1]
                # The password change replaces the session, so use the new one.
                resp = {**resp, **self.finish_password_change_v2(
                    change["passwordChangeToken"], spwd, kb, resp["sessionToken"], keys)}
                stretchpwd_final = spwd
                key_fetch_token = resp.get("keyFetchToken2")
            except Exception as inst:
                # Keep the v1 session, e.g. when it is not verified yet.
                print("Warning! v2 key stretch auto upgrade failed! Continuing with v1 login. " +
                      f"Reason: {inst}")
                stretchpwd_final = spwd.v1
                key_fetch_token = resp.get("keyFetchToken")
        elif self.key_stretch_version == 2:
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
        auth = FxATokenBearerAuth(key_fetch_token, "keyFetchToken", self.apiclient)
        resp = self.apiclient.get(url, auth=auth)
        bundle = unhexlify(resp["bundle"])
        keys = auth.unbundle("account/keys", bundle)
        return unwrap_keys(keys, stretchpwd)

    def change_password(self, email, oldpwd=None, newpwd=None,
                        oldstretchpwd=None, newstretchpwd=None, *, session_token):
        """Change the password using a verified ``session_token``.

        The server deletes every token on the account, so the returned
        response carries the replacement ``sessionToken``.
        """
        exactly_one_of(oldpwd, "oldpwd", oldstretchpwd, "oldstretchpwd")
        exactly_one_of(newpwd, "newpwd", newstretchpwd, "newstretchpwd")

        if self.key_stretch_version == 2:
            version, salt = self.get_key_stretch_version(email)
            old_spwd = StretchedPassword(version, email, salt, oldpwd, oldstretchpwd)
            new_spwd = StretchedPassword(2, email, salt, newpwd, newstretchpwd)

            if version == 2:
                resp = self.start_password_change(email, old_spwd.v2, session_token)
                kb = self.fetch_keys(resp["keyFetchToken2"], old_spwd.v2)[1]
            else:
                resp = self.start_password_change(email, old_spwd.v1, session_token)
                kb = self.fetch_keys(resp["keyFetchToken"], old_spwd.v1)[1]

            return self.finish_password_change_v2(
                resp["passwordChangeToken"],
                new_spwd,
                kb,
                session_token)
        else:
            if oldpwd:
                oldstretchpwd = quick_stretch_password(email, oldpwd)
            if newpwd:
                newstretchpwd = quick_stretch_password(email, newpwd)
            resp = self.start_password_change(email, oldstretchpwd, session_token)
            kb = self.fetch_keys(resp["keyFetchToken"], oldstretchpwd)[1]
            new_wrapkb = derive_wrap_kb(kb, newstretchpwd)
            return self.finish_password_change(
                resp["passwordChangeToken"], newstretchpwd, new_wrapkb, session_token)

    def start_password_change(self, email, stretchpwd, session_token):
        body = {
            "email": email,
            "oldAuthPW": hexstr(derive_auth_pw(stretchpwd)),
        }
        auth = FxATokenBearerAuth(session_token, "sessionToken", self.apiclient)
        return self.apiclient.post("/password/change/start", body, auth=auth)

    def finish_password_change(self, token, stretchpwd, wrapkb, session_token):
        body = {
            "authPW": hexstr(derive_auth_pw(stretchpwd)),
            "wrapKb": hexstr(wrapkb),
        }
        return self._finish_password_change(token, body, session_token)

    def finish_password_change_v2(self, token, spwd, kb, session_token, keys=False):
        body = {
            "authPW": spwd.get_auth_pw_v1(),
            "wrapKb": spwd.get_wrapkb_v1(kb),
            "authPWVersion2": spwd.get_auth_pw_v2(),
            "wrapKbVersion2": spwd.get_wrapkb_v2(kb),
            "clientSalt": spwd.v2_salt,
        }
        return self._finish_password_change(token, body, session_token, keys)

    def _finish_password_change(self, token, body, session_token, keys=False):
        # Lets the replacement session keep the current session's verified state.
        body["sessionToken"] = FxATokenBearerAuth(session_token, "sessionToken").id
        url = "/password/change/finish"
        if keys:
            url += "?keys=true"
        auth = FxATokenBearerAuth(token, "passwordChangeToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

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
        auth = FxATokenBearerAuth(token, "accountResetToken", self.apiclient)
        self.apiclient.post(url, body, auth=auth)

    def send_reset_code(self, email, service=None):
        """Email a one-time code that starts a password reset for ``email``.

        The server issues no token until the code is verified, so the
        returned :class:`PasswordForgotToken` is only usable through
        :meth:`PasswordForgotToken.verify_code`.
        """
        body = {
            "email": email,
        }
        if service is not None:
            body["service"] = service
        url = "/password/forgot/send_otp"
        self.apiclient.post(url, body)
        return PasswordForgotToken(self, email, service=service)

    def verify_reset_otp(self, email, code):
        """Exchange the emailed one-time code for a ``passwordForgotToken``.

        Returns the raw response: ``token`` (the passwordForgotToken), the
        server-issued ``code`` that :meth:`verify_reset_code` expects,
        ``uid`` and ``emailToHashWith``.
        """
        body = {
            "email": email,
            "code": code,
        }
        url = "/password/forgot/verify_otp"
        return self.apiclient.post(url, body)

    def verify_reset_code(self, token, code):
        body = {
            "code": code,
        }
        url = "/password/forgot/verify_code"
        auth = FxATokenBearerAuth(token, "passwordForgotToken", self.apiclient)
        return self.apiclient.post(url, body, auth=auth)

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
                 auth_timestamp=0):
        self.client = client
        self.email = email
        self.uid = uid
        self.token = token
        self.verified = verified
        self.verificationMethod = verificationMethod
        self.auth_timestamp = auth_timestamp
        self.keys = None
        self._auth = FxATokenBearerAuth(token, "sessionToken", self.apiclient)
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

    def mfa_request_otp(self, action):
        """Ask the server to email a one-time code for a sensitive ``action``.

        The code arrives in the ``X-Account-Change-Verify-Code`` header of the
        email and is exchanged for a short-lived MFA token with
        :meth:`mfa_verify_otp`. Requires a verified session.
        """
        url = "/mfa/otp/request"
        return self.apiclient.post(url, {"action": action}, auth=self._auth)

    def mfa_verify_otp(self, code, action):
        """Exchange an emailed one-time code for an MFA token.

        The returned token is a JWT scoped to ``action`` and is what the
        ``/mfa/*`` routes accept in place of the session token.
        """
        url = "/mfa/otp/verify"
        body = {
            "code": code,
            "action": action,
        }
        resp = self.apiclient.post(url, body, auth=self._auth)
        return resp["accessToken"]

    def totp_create(self, mfa_token):
        """Start TOTP setup and return the shared secret and QR code URL.

        ``mfa_token`` comes from :meth:`mfa_verify_otp` with the ``"2fa"``
        action. Nothing is stored on the account until
        :meth:`totp_setup_complete` succeeds.
        """
        url = "/mfa/totp/create"
        return self.apiclient.post(url, {}, auth=BearerTokenAuth(mfa_token))

    def totp_setup_verify(self, mfa_token, code):
        """Prove possession of the pending TOTP secret with a current code."""
        url = "/mfa/totp/setup/verify"
        body = {
            "code": code,
        }
        resp = self.apiclient.post(url, body, auth=BearerTokenAuth(mfa_token))
        return resp["success"]

    def totp_setup_complete(self, mfa_token):
        """Enable TOTP on the account once :meth:`totp_setup_verify` passed."""
        url = "/mfa/totp/setup/complete"
        resp = self.apiclient.post(url, {}, auth=BearerTokenAuth(mfa_token))
        return resp["success"]

    def totp_exists(self):
        url = "/totp/exists"
        resp = self.apiclient.get(url, auth=self._auth)
        return resp["exists"]

    def totp_delete(self, mfa_token):
        """Remove TOTP from the account. ``mfa_token`` needs the ``"2fa"`` action."""
        url = "/mfa/totp/destroy"
        return self.apiclient.post(url, {}, auth=BearerTokenAuth(mfa_token))

    def totp_verify(self, code):
        url = "/session/verify/totp"
        body = {
            "code": code,
        }
        resp = self.apiclient.post(url, body, auth=self._auth)
        if resp["success"]:
            self.verified = True

        return resp["success"]

    def change_password(self, oldpwd, newpwd,
                        oldstretchpwd=None, newstretchpwd=None):
        resp = self.client.change_password(self.email, oldpwd, newpwd,
                                           oldstretchpwd, newstretchpwd,
                                           session_token=self.token)
        self._use_replacement_session(resp)
        return resp

    def start_password_change(self, stretchpwd):
        return self.client.start_password_change(self.email, stretchpwd, self.token)

    def finish_password_change(self, token, stretchpwd, wrapkb):
        resp = self.client.finish_password_change(token, stretchpwd, wrapkb, self.token)
        self._use_replacement_session(resp)
        return resp

    def _use_replacement_session(self, resp):
        # A password change deletes this session; switch to the one the server issued.
        self.token = resp["sessionToken"]
        self._auth = FxATokenBearerAuth(self.token, "sessionToken", self.apiclient)

    def get_random_bytes(self):
        # XXX TODO: sanity-check the schema of the returned response
        return self.client.get_random_bytes()


class PasswordForgotToken:
    """A password reset in progress, started by :meth:`Client.send_reset_code`.

    The auth server emails an 8-digit one-time code. Pass it to
    :meth:`verify_code` to obtain the ``accountResetToken`` that
    :meth:`Client.reset_account` needs. ``token``, ``uid`` and
    ``email_to_hash_with`` are populated once the code has been verified.
    """

    def __init__(self, client, email, service=None):
        self.client = client
        self.email = email
        self.service = service
        self.token = None
        self.uid = None
        self.email_to_hash_with = None

    def verify_code(self, code):
        otp = self.client.verify_reset_otp(self.email, code)
        self.token = otp["token"]
        self.uid = otp["uid"]
        self.email_to_hash_with = otp["emailToHashWith"]
        resp = self.client.verify_reset_code(self.token, otp["code"])
        return resp["accountResetToken"]

    def resend_code(self):
        """Email a fresh one-time code."""
        self.client.send_reset_code(self.email, service=self.service)


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
