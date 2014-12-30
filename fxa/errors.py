# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

fxa.errors:  basic exception classes for PyFxA

"""


class Error(Exception):
    """Base error class for all PyFxA exceptions."""
    pass


class OutOfProtocolError(Error):
    """Base error class for undefined out-of-protocol error conditions.

    Such errors will typically be raised if a server is behaving badly, e.g.
    returning invalid JSON responses.  These are typically fatal as they
    mean that a piece of the infra is not acting as it should.
    """
    pass


class InProtocolError(Error):
    """Base error class for defined in-protocol error conditions.

    Such errors will always present as a well-formed JSON response from a
    server, and will include a code, errno, error message etc.  We reflect
    these properties as attributes of the exception object.
    """

    def __init__(self, details={}):
        self.details = details
        self.code = details.get("code", 500)
        self.errno = details.get("errno", 999)
        self.error = details.get("error", "unknown error")
        self.info = details.get("info", None)
        message = details.get("message", self.error)
        super(InProtocolError, self).__init__(message)


class ClientError(InProtocolError):
    """Base error class for in-protocol errors caused by client behaviour."""
    pass


class ServerError(InProtocolError):
    """Base error class for in-protocol errors caused by server behaviour."""
    pass


class TrustError(Error):
    """Base error class for security conditions being violated.

    Examples might include a bad signature on some data, a mismatched
    audience on an assertion, or a missing scope on an OAuth token.
    """
    pass


class ScopeMismatchError(TrustError):
    """Error raised when the OAuth scopes do not match."""

    def __init__(self, provided, required):
        message = "scope {0} does not match {1}".format(provided, required)
        super(ScopeMismatchError, self).__init__(message)
