===========================================================
PyFxA: Python library for interacting with Firefox Accounts
===========================================================

This is python library for interacting with the Firefox Accounts ecosystem.
It's highly experimental and subject to change.  Eventually, it is planned
to provide easy support for the following features:

  * being a direct firefox accounts authentication client
  * being an FxA OAuth Relier
  * being an FxA OAuth Service Provider
  * accessing attached services

But none of that is really ready yet; caveat emptor.

Currently, basic auth-server operations should work like so::

    from fxa.core import Client

    client = Client("https://api.accounts.firefox.com")
    client.create_account("test@example.com", "MySecretPassword")

    session = client.login("test@example.com", "MySecretPassword")
    cert = session.sign_certificate(myPublicKey)
    session.change_password("MySecretPassword", "ThisIsEvenMoreSecret")


Here's some sketchy notes on things we should add in this module:

  * restmail.net interface to make testing easy
  * easy preVerifyToken support for testing purposes
