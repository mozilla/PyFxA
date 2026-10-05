# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import sys
import unittest

from fxa.__main__ import main as fxa_main
from fxa.tests.mock_utilities import (
    mock, mocked_core_client, mocked_oauth_client)
from fxa.errors import ClientError
from fxa.tools.bearer import get_bearer_token
from fxa.tools.create_user import create_new_fxa_account

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
            core_client.return_value.login.return_value,
            'profile'
        )


class TestCreateNewFxaAccount(unittest.TestCase):
    server_url = "https://api-accounts.stage.mozaws.net/v1"

    @mock.patch('fxa.tools.create_user.TestEmailAccount')
    @mock.patch('fxa.core.Client')
    def test_verifies_new_account_with_email_code(self, core_client, email_acct):
        email_acct.return_value.wait_for_email.return_value = {
            "headers": {"x-verify-code": "123456"}}
        calls = mock.Mock()
        calls.attach_mock(email_acct.return_value.clear, "clear")
        calls.attach_mock(core_client.return_value.create_account, "create_account")
        email, password = create_new_fxa_account(
            fxa_user_salt="c2FsdA==", account_server_url=self.server_url)
        # The inbox is cleared first, so an earlier run's code cannot be read.
        self.assertEqual([c[0] for c in calls.mock_calls][:2], ["clear", "create_account"])
        core_client.return_value.create_account.assert_called_once_with(
            email, password=password)
        session = core_client.return_value.create_account.return_value
        session.verify_email_code.assert_called_once_with("123456")

    @mock.patch('fxa.tools.create_user.TestEmailAccount')
    @mock.patch('fxa.core.Client')
    def test_existing_account_skips_verification(self, core_client, email_acct):
        core_client.return_value.create_account.side_effect = ClientError(
            {"errno": 101})
        create_new_fxa_account(account_server_url=self.server_url)
        email_acct.return_value.wait_for_email.assert_not_called()

    @mock.patch('fxa.tools.create_user.TestEmailAccount')
    @mock.patch('fxa.core.Client')
    def test_raises_when_verification_email_missing(self, core_client, email_acct):
        email_acct.return_value.wait_for_email.return_value = None
        with self.assertRaises(RuntimeError):
            create_new_fxa_account(account_server_url=self.server_url)

    @mock.patch('fxa.__main__.create_new_fxa_account',
                side_effect=RuntimeError("Verification email was not received"))
    def test_cli_logs_missing_email_and_exits(self, _create):
        argv = ["fxa", "--create-user",
                "--account-server", "https://api-accounts.stage.mozaws.net/v1"]
        with mock.patch.object(sys, "argv", argv), \
                self.assertLogs("fxa-client", level="ERROR") as logs, \
                self.assertRaises(SystemExit) as exit_:
            fxa_main()
        self.assertEqual(exit_.exception.code, 1)
        self.assertIn("Verification email was not received", logs.output[0])
