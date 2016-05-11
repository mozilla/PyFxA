# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from fxa.tests.utils import unittest
from fxa.tests.mock_utilities import (
    mock, mocked_core_client, mocked_oauth_client)
from fxa.tools.bearer import get_bearer_token
from fxa.tools.browserid import get_browserid_assertion


class TestGetBearerToken(unittest.TestCase):
    def test_account_server_url_is_mandatory(self):
        try:
            get_bearer_token("email", "password",
                             oauth_server_url="oauth_server_url",
                             client_id="client_id")
        except ValueError as e:
            self.assertEqual("%s" % e, 'Please define an account_server_url.')
        else:
            self.fail("ValueError not raised")

    def test_oauth_server_url_is_mandatory(self):
        try:
            get_bearer_token("email", "password",
                             account_server_url="account_server_url",
                             client_id="client_id")
        except ValueError as e:
            self.assertEqual("%s" % e, 'Please define an oauth_server_url.')
        else:
            self.fail("ValueError not raised")

    def test_client_id_is_mandatory(self):
        try:
            get_bearer_token("email", "password",
                             account_server_url="account_server_url",
                             oauth_server_url="oauth_server_url")
        except ValueError as e:
            self.assertEqual("%s" % e, 'Please define a client_id.')
        else:
            self.fail("ValueError not raised")

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    @mock.patch('fxa.oauth.Client',
                return_value=mocked_oauth_client())
    def test_scopes_default_to_profile(self, oauth_client, core_client):
        get_bearer_token("email", "password",
                         client_id="543210789456",
                         account_server_url="account_server_url",
                         oauth_server_url="oauth_server_url")
        oauth_client().authorize_token.assert_called_with(
            'abcd', 'profile', '543210789456')


class TestGetBrowserIDAssertion(unittest.TestCase):
    def test_account_server_url_is_mandatory(self):
        try:
            get_browserid_assertion("email", "password", "audience")
        except ValueError as e:
            self.assertEqual("%s" % e, 'Please define an account_server_url.')
        else:
            self.fail("ValueError not raised")

    @mock.patch('fxa.core.Client',
                return_value=mocked_core_client())
    def test_duration_and_audience_are_used(self, core_client):
        get_browserid_assertion("email", "password", "audience",
                                account_server_url="account_server_url",
                                duration=3600 * 1000)
        core_client().login().get_identity_assertion.assert_called_with(
            audience='audience', duration=3600 * 1000)
