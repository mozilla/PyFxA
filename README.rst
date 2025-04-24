===========================================================
PyFxA: Python library for interacting with Mozilla Accounts
===========================================================

This is python library for interacting with the Mozilla Accounts (formerly known as the Firefox Accounts) ecosystem.

Eventually, it is planned to provide easy support for the following features:

* being a direct mozilla accounts authentication client
* being an FxA OAuth Service Provider
* accessing attached services
* helps interactions with Firefox Account servers with requests Authentication plugins.

But none of that is ready yet; caveat emptor.


Mozilla Accounts
================

Currently, basic auth-server operations should work like so:

.. code-block:: python

    from fxa.core import Client

    client = Client("https://api.accounts.firefox.com")
    client.create_account("test@example.com", "MySecretPassword")

    session = client.login("test@example.com", "MySecretPassword")
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


Passing tokens to other applications
===================================================

PyFxA provides a ``fxa-client`` that you can use to export Bearer
Tokens.


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


With Requests
=============

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



=====================
Contributing to PyFxA
=====================

The basic requirements are:

- Python 3.12.2 or higher
- Pip 24.0

To get started:

.. code:: bash

    pip install '.[dev]'
    pip install .

To run tests:

.. code:: bash

    pytest

If you'd like to run all supported versions of Python, install `hatch` via `pip` or `pipx`:

.. code:: bash

    pipx install hatch

Once installed you can run the tests in all supported Python environments with:

.. code:: bash

    hatch run test:cov

To run the tests with specific Python version you can specify this with hatch:

.. code:: bash

    hatch run +py=3.10 test:cov
