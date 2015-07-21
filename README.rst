===========================================================
PyFxA: Python library for interacting with Firefox Accounts
===========================================================

This is python library for interacting with the Firefox Accounts ecosystem.
It's highly experimental and subject to change.  Eventually, it is planned
to provide easy support for the following features:

  * being a direct firefox accounts authentication client
  * being an FxA OAuth Service Provider
  * accessing attached services

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


Using Firefox Account BrowserID with Requests
=============================================

You can use the ``FxABrowserIdAuth`` to build the BrowserId assertion:

.. code-block:: python

    from fxa.core import Client
    from fxa.requests import FxABrowserIdAuth
    from fxa.tests.utils import TestEmailAccount

    email = acct.email
    password = "MySecretPassword"

    raw_resp = requests.get('https://token.services.mozilla.com/1.0/sync/1.5',
                            auth=FxABrowserIdAuth(email, password))

    raw_resp.raise_for_status()
    resp = raw_resp.json()
    user_id = resp['uid']


Using Firefox Account BrowserID with HTTPie
===========================================

You can use the httpie plugin provided with PyFxA to build the BrowserID request:

.. code-block:: http

    http GET -v https://token.services.mozilla.com/1.0/sync/1.5 \
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

    You can configure the audience by settings the BID_AUDIENCE environment variable.
