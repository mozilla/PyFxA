# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Python library for interacting with the Firefox Accounts ecosystem.

"""

__ver_major__ = 0
__ver_minor__ = 0
__ver_patch__ = 6
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


def monkey_patch_for_gevent():
    import fxa._utils
    import grequests
    fxa._utils.requests = grequests

try:
    # Verify we are using the Py2 urllib3 version with OpenSSL installed
    from requests.packages.urllib3.contrib import pyopenssl
except ImportError:
    pass
else:
    pyopenssl.inject_into_urllib3()
