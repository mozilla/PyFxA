===========================================================
PyFxA: Python library for interacting with Firefox Accounts
===========================================================

This is python library for interacting with the Firefox Accounts ecosystem.

Eventually, it is planned to provide easy support for the following features:

* being a direct firefox accounts authentication client
* being an FxA OAuth Service Provider
* accessing attached services
* helps interactions with Firefox Account servers wiht requests Authentication plugins.

But none of that is ready yet; caveat emptor.


Firefox Accounts
================

Currently, basic auth-server operations should work like so:

.. code-block:: python

    from fxa.core import Client

    client = Client("https://api.accounts.firefox.com")
    client.create_account("test@example.com", "MySecretPassword")

    session = client.login("test@example.com", "MySecretPassword")
    cert = session.sign_certificate(myPublicKey)
    session.change_password("MySecretPassword", "ThisIsEvenMoreSecret")


FxA OAuth Relier
================

Trade the authentication code against a longer lived OAuth token:

.. code-block:: python

    from fxa.oauth import Client

    client = Client()
    token = client.trade_code("client-id", "client-secret", "code-1234")


Verify an OAuth token:

.. code-block:: python

    from fxa.oauth import Client
    from fxa.errors import ClientError

    client = Client()

    try:
        profile = client.verify_token("123456...")
    except ClientError:
        print "Invalid token"

    print("User id", profile["user"])


Testing email addresses
=======================

There's also very basic integration with restmail.net, to allow for
testing with live email addresses.  It works like this:

.. code-block:: python

    from fxa.core import Client
    from fxa.tests.utils import TestEmailAccount

    # Create a testing account using an @restmail.net address.
    acct = TestEmailAccount()
    client = Client("https://api.accounts.firefox.com")
    session = client.create_account(acct.email, "MySecretPassword")

    # Verify the account using the code from email.
    acct.fetch()
    for m in acct.messages:
        if "x-verify-code" in m["headers"]:
            session.verify_email_code(m["headers"]["x-verify-code"])

    ...

    # Destroy the account once you're done with it.
    acct.clear()
    client.destroy_account(acct.email, "MySecretPassword")


Passing tokens and assertions to other applications
===================================================

PyFxA provides a ``fxa-client`` that you can use to export Bearer
Tokens and Browser ID assertions.


Get a Bearer Token for an existing account
------------------------------------------

.. code-block:: bash

    fxa-client --bearer --auth you@domain.tld \
        --account-server https://api.accounts.firefox.com/v1 \
        --oauth-server https://oauth.accounts.firefox.com/v1

    Please enter a password for you@domain.tld: 

    # ---- BEARER TOKEN INFO ----
    # User: you@domain.tld
    # Scopes: profile
    # Account: https://api.accounts.firefox.com/v1
    # Oauth: https://oauth.accounts.firefox.com/v1
    # ---------------------------
    export OAUTH_BEARER_TOKEN="3f5106b203c...b728ef93fe29203aad44ee816a45b2f2ff57a6aed7a3"


Create a new account Bearer Token on stage
------------------------------------------

.. code-block:: bash

    fxa-client --bearer --create --prefix hello

    # ---- BEARER TOKEN INFO ----
    # User: hello-89331eba46e970dc1686ba2dc4583fc9@restmail.net
    # Scopes: profile
    # Account: https://api-accounts.stage.mozaws.net/v1
    # Oauth: https://oauth.stage.mozaws.net/v1
    # ---------------------------
    export OAUTH_BEARER_TOKEN="ecb5285d59b28e6768fe60d76e6994877ffb16d3232c...72bdee05ea8a5"


Create a new account BrowserID assertion on stage
-------------------------------------------------

.. code-block:: bash

    fxa-client --browserid --create --audience https://token.stage.mozaws.net/ --prefix syncto
    # ---- BROWSER ID ASSERTION INFO ----
    # User: syncto-5bcf63598bf6026a6833035821742d3e@restmail.net
    # Audience: https://token.stage.mozaws.net/
    # Account: https://api-accounts.stage.mozaws.net/v1
    # ------------------------------------
    export FXA_BROWSERID_ASSERTION="eyJhbGciOiJSUzI1NiJ9.eyJw......VNKcPu6Uc9Y4pCuGcdM0UwaA"
    export FXA_CLIENT_STATE="abaa31cc3b16aaf6759f2cba164a54be"


With Requests
=============

Using Firefox Account BrowserID with Requests
---------------------------------------------

You can use the ``FxABrowserIDAuth`` to build the BrowserID assertion:

.. code-block:: python

    from fxa.core import Client
    from fxa.plugins.requests import FxABrowserIDAuth

    email = acct.email
    password = "MySecretPassword"

    raw_resp = requests.get('https://token.services.mozilla.com/1.0/sync/1.5',
                            auth=FxABrowserIDAuth(email, password,
                                                  with_client_state=True))

    raw_resp.raise_for_status()
    resp = raw_resp.json()
    user_id = resp['uid']


Using Firefox Account Bearer Token with Requests
------------------------------------------------

You can use the ``FxABearerTokenAuth`` to build the Bearer Token:

.. code-block:: python

    from fxa.core import Client
    from fxa.plugins.requests import FxABearerTokenAuth

    email = acct.email
    password = "MySecretPassword"

    raw_resp = requests.get('https://profile.accounts.firefox.com/v1/profile',
                            auth=FxABearerTokenAuth(email, password,
                                                    ['profile'], client_id))

    raw_resp.raise_for_status()
    resp = raw_resp.json()
    user_id = resp['uid']


With HTTPie
===========

Using Firefox Account BrowserID with HTTPie
-------------------------------------------

You can use the httpie plugin provided with PyFxA to build the BrowserID request:

.. code-block:: http

    BID_WITH_CLIENT_STATE=True \
        http GET https://token.services.mozilla.com/1.0/sync/1.5 \
        --auth-type=fxa-browserid --auth "email:password" -v

    GET /1.0/sync/1.5 HTTP/1.1
    Accept: */*
    Accept-Encoding: gzip, deflate
    Authorization: BrowserID eyJhbG..._EqaQ
    Connection: keep-alive
    Host: token.services.mozilla.com
    User-Agent: HTTPie/0.9.2
    X-Client-State: 97b945...920fac4d4d5f0dc6...2992

    HTTP/1.1 200 OK
    Access-Control-Allow-Credentials: true
    Access-Control-Allow-Headers: DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization,X-Conditions-Accepted
    Access-Control-Allow-Methods: GET, POST, OPTIONS
    Access-Control-Max-Age: 1728000
    Connection: keep-alive
    Content-Length: 414
    Content-Type: application/json; charset=UTF-8
    Date: Tue, 21 Jul 2015 10:48:42 GMT
    X-Timestamp: 1437475722

    {
        "api_endpoint": "https://sync-230-us-west-2.sync.services.mozilla.com/1.5/99283757",
        "duration": 3600,
        "hashalg": "sha256",
        "id": "eyJub2RlI....FlYzdiMCIsICJ1aWQiOiAyMDIzODc3NX2Bvj5zv..7S2jRaw__-....eh3hiSVWA==",
        "key": "lSw-MvgK....ebu9JsX-yXS70NkiXu....6wWgVzU0Q=",
        "uid": 99283757
    }

.. note::

    You can configure the audience by settings the ``BID_AUDIENCE``
    environment variable.

	You can also compute the Token Server client state using the
	``BID_WITH_CLIENT_STATE`` environment variable.


Using Firefox Account Bearer Tokens with HTTPie
-----------------------------------------------

You can use the httpie plugin provided with PyFxA to build the Bearer
token request:

.. code-block:: http

    $ http GET https://profile.accounts.firefox.com/v1/profile \
        --auth-type fxa-bearer --auth "email:password" -v

    GET /v1/profile HTTP/1.1
    Accept: */*
    Accept-Encoding: gzip, deflate
    Authorization: Bearer 98e05e12ba...0d61231e88daf91
    Connection: keep-alive
    Host: profile.accounts.firefox.com
    User-Agent: HTTPie/0.9.2

    HTTP/1.1 200 OK
    Connection: keep-alive
    Content-Length: 92
    Content-Type: application/json; charset=utf-8
    Date: Tue, 21 Jul 2015 14:47:32 GMT
    Server: nginx
    access-control-allow-headers: Authorization, Content-Type, If-None-Match
    access-control-allow-methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
    access-control-allow-origin: *
    access-control-expose-headers: WWW-Authenticate, Server-Authorization
    access-control-max-age: 86400
    cache-control: no-cache
    content-encoding: gzip
    etag: "d1cf22901b3e3be527c06e27689be705bb22a172"
    strict-transport-security: max-age=15552000; includeSubdomains
    vary: accept-encoding

    {
        "email": "email@address.com",
        "uid": "63b91ca4ec19ad79f320eaf5815d75e9"
    }

.. note::

    You can configure the following:

      - FXA_CLIENT_ID: To choose the CLIENT_ID (default to Firefox Dev id)
      - FXA_SCOPES: To choose the list of scopes
      - FXA_ACCOUNT_SERVER_URL: To select the account server url
        (default to: https://api.accounts.firefox.com/v1)
      - FXA_OAUTH_SERVER_URL: To select the oauth server url
        (default to: https://oauth.accounts.firefox.com/v1)
