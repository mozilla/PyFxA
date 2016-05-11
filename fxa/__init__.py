# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Python library for interacting with the Firefox Accounts ecosystem.

"""

__version__ = '0.2.0'
__ver_tuple__ = tuple(__version__.split('.'))


def monkey_patch_for_gevent():
    import fxa._utils
    import grequests
    fxa._utils.requests = grequests

try:
    # Verify we are using the Py2 urllib3 version with OpenSSL installed
    from requests.packages.urllib3.contrib import pyopenssl
except ImportError:  # pragma: no cover
    pass
else:
    pyopenssl.inject_into_urllib3()
