# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import sys
import time
import random
import requests
from binascii import unhexlify
from six import binary_type
from six.moves.urllib.parse import urlparse, urljoin

from fxa._utils import uniq

if sys.version_info >= (2, 7):
    import unittest  # NOQA
else:
    import unittest2 as unittest  # NOQA


DUMMY_EMAIL = "PyFxATester@restmail.net"
DUMMY_PASSWORD = "l33tP@55W0rd"
DUMMY_STRETCHED_PASSWORD = unhexlify(
    "59eb52f6ee5ebe2b599161aaa9b171c3baa8bed594d4e2a8b4b539fb9eba8368"
)


def mutate_one_byte(input):
    """Randomly change one character in the given bytestring.

    This is handy for testing tokens, signatures, and other things
    that are supposed to fail if they're tampered with.
    """
    if not input:
        raise ValueError("cannot mutate empty string")
    pos = random.randint(0, len(input) - 1)
    if input[pos] == "a":
        replacement = "b"
    else:
        replacement = "a"
    if isinstance(input, binary_type):
        replacement = replacement.encode("ascii")
    return input[:pos] + replacement + input[pos + 1:]


class TestEmailAccount(object):
    """A live email account that can be used for testing purposes.

    This is a simple interface to http://restmail.net that allows you to
    use a live email account for testing purposes.  Instantiated with no
    arguments, you will get a randomly-generated <something>@restmail.net
    address and the ability to read email delivered there via the following
    API:

        * email:     the string email address for this account
        * messages:  list of messages currently in the account, newest first
        * fetch():   update list of messages currently in the account
        * clear():   delete any messages stored in the account

    To customize the email address, pass a string as first argument.  It can
    include string-formatting placeholders for "{unique}" and "{hostname}" if
    you want these to be filled in automatically.
    """

    DEFAULT_SERVER_URL = "http://restmail.net"

    def __init__(self, email=None, server_url=None):
        if server_url is None:
            server_url = self.DEFAULT_SERVER_URL
        if email is None:
            email = "test-{uniq}@{hostname}"
        hostname = urlparse(server_url).hostname
        self.email = email.format(uniq=uniq(), hostname=hostname)
        self.server_url = server_url
        if self.email.endswith("@" + hostname):
            userid = self.email.rsplit("@", 1)[0]
        else:
            userid = self.email
        self.user_url = urljoin(self.server_url, "/mail/" + userid)
        self.messages = []

    def fetch(self):
        resp = requests.get(self.user_url)
        resp.raise_for_status()
        self.messages[:] = resp.json()

    def clear(self):
        resp = requests.delete(self.user_url)
        resp.raise_for_status()
        self.messages[:] = []

    def find_email(self, callback=lambda: True):
        for m in self.messages:
            if callback(m):
                return m
        return None

    def wait_for_email(self, callback=lambda: True, timeout=30):
        start_time = time.time()
        while True:
            self.fetch()
            m = self.find_email(callback)
            if m is not None:
                return m
            if start_time + timeout < time.time():
                return None
