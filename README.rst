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
    token = client.trade_token("client-id", "client-secret", "code-1234")


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
