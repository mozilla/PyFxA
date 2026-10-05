# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Deprecated alias for :mod:`fxa.testing`.

The test suite itself is no longer installed with the package. This module
is kept so that existing ``from fxa.tests.utils import TestEmailAccount``
imports keep working; new code should import from ``fxa.testing``.
"""
import unittest  # NOQA: F401 - re-exported for backwards compatibility
import warnings

from fxa.testing import (  # NOQA: F401
    DUMMY_EMAIL,
    DUMMY_PASSWORD,
    DUMMY_SALT_CORE_V2,
    DUMMY_SALT_V2,
    TestEmailAccount,
    mutate_one_byte,
)

warnings.warn(
    "fxa.tests.utils is deprecated and will be removed in a future release; "
    "import from fxa.testing instead.",
    DeprecationWarning,
    stacklevel=2,
)
