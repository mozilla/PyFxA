#!/usr/bin/env python
from __future__ import print_function
import argparse
import getpass
import os
import re
import sys

from fxa.errors import ClientError
from fxa.tools.bearer import get_bearer_token
from fxa.tools.browserid import get_browserid_assertion
from fxa.tools.fxa import create_new_fxa_account

FXA_API_URL = "https://api-accounts.stage.mozaws.net/v1"
FXA_OAUTH_URL = "https://oauth.stage.mozaws.net/v1"
DEFAULT_CLIENT_ID = "5882386c6d801776"  # Firefox dev Client ID


def main(args=None):
    """The main routine."""
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="PyFxA commands")
    parser.add_argument('--bearer',
                        help='Generate a Bearer token',
                        dest='bearer',
                        action='store_true')

    parser.add_argument('--browserid', '--bid',
                        help='Generate a BrowserID assertion',
                        dest='browserid',
                        action='store_true')

    parser.add_argument('--create', '-c',
                        help='Create a new user',
                        dest='create',
                        action='store_true')
    parser.add_argument('--auth', '-u',
                        help='User credentials',
                        dest='auth',
                        required=False)
    parser.add_argument('--out', '-o', '-O',
                        help='Output file',
                        dest='output_file',
                        required=False,
                        default=None)

    parser.add_argument('--verbose', '-v',
                        help='Display status',
                        dest='verbose',
                        action='store_true')

    # Creation args
    parser.add_argument('--user-salt',
                        help=('Salt used to calculate the user credentials. '
                              '(Random by default)'),
                        dest='fxa_user_salt',
                        required=False)

    # FxA server configuration
    parser.add_argument('--account-server',
                        help='Firefox Account server URL',
                        dest='account_server_url',
                        required=False,
                        default=FXA_API_URL)

    parser.add_argument('--oauth-server',
                        help='Firefox Account OAuth server URL',
                        dest='oauth_server_url',
                        required=False,
                        default=FXA_OAUTH_URL)

    parser.add_argument('--client-id',
                        help='Firefox Account OAuth client id.',
                        dest='client_id',
                        required=False,
                        default=DEFAULT_CLIENT_ID)

    parser.add_argument('--scopes',
                        help='Firefox Account OAuth scopes.',
                        dest='scopes',
                        required=False,
                        default='profile')

    parser.add_argument('--audience',
                        help='Firefox BrowserID assertion audience.',
                        dest='audience',
                        required=False,
                        default='https://token.services.mozilla.com/')

    parser.add_argument('--duration',
                        help='Firefox BrowserID assertion duration.',
                        dest='duration',
                        required=False,
                        default='3600')

    args = vars(parser.parse_args())
    create = args['create']
    auth = args.get('auth')
    verbose = args['verbose']

    account_server_url = args['account_server_url']
    oauth_server_url = args['oauth_server_url']

    fd = sys.stdout  # By default write to the standard output
    out = args.get('output_file')
    if out:
        out = os.path.abspath(out)
        file_path = os.path.dirname(out)
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        fd = open(out, 'w')

    if auth:
        # Ask for the user password if needed
        auth = auth.split(':', 1)
        if len(auth) < 2:
            email = auth[0]
            password = getpass.getpass('Please enter a password for %s: '
                                       % auth[0])
    elif create:
        # Create a new user
        if verbose:
            print('# Creating the account...', end='', file=sys.stderr)
            sys.stderr.flush()

        try:
            email, password = create_new_fxa_account(
                os.getenv('FXA_USER_SALT', args.get('fxa_user_salt')),
                args['account_server_url'])
        except (ClientError, ValueError) as e:
            print('ERROR:\t %s' % e, file=sys.stderr)
            sys.exit(1)

        if verbose:
            print("\b\b\b\t [OK]", file=sys.stderr)

    if args['bearer']:
        # Generate a Bearer Token for the user and write it into a file.
        scopes = [s.strip() for s in re.split(';|,|\t|\n', args['scopes'])
                  if s.strip()]
        client_id = args['client_id']

        if verbose:
            print('# Generating the Bearer Token...', end='', file=sys.stderr)
            sys.stderr.flush()

        try:
            token = get_bearer_token(email, password, scopes,
                                     account_server_url,
                                     oauth_server_url, client_id)
        except ClientError as e:
            print('ERROR:\t %s' % e, file=sys.stderr)
            sys.exit(1)

        if verbose:
            print("\b\b\b\t [OK]", file=sys.stderr)

        print('# ---- BEARER TOKEN INFO ----', file=fd)
        print('# User: %s' % email, file=fd)
        print('# Scopes: %s' % ' '.join(scopes), file=fd)
        print('# Account: %s' % account_server_url, file=fd)
        print('# Oauth: %s' % oauth_server_url, file=fd)
        print('# Client ID: %s' % client_id, file=fd)
        print('# ---------------------------', file=fd)
        print('export OAUTH_BEARER_TOKEN="%s"\n' % token, file=fd)

    if args['browserid']:
        # Generate a BrowserID assertion for the user and write it into a file.
        audience = args['audience']
        duration = int(args['duration'])

        if verbose:
            print('# Creating the token...', end='', file=sys.stderr)
            sys.stderr.flush()

        try:
            bid_assertion, client_state = get_browserid_assertion(
                email, password, audience, account_server_url, duration)
        except ClientError as e:
            print('ERROR:\t %s' % e, file=sys.stderr)
            sys.exit(1)

        if verbose:
            print("\b\b\b\t [OK]", file=sys.stderr)

        print('# ---- BROWSER ID ASSERTION INFO ----', file=fd)
        print('# User: %s' % email, file=fd)
        print('# Audience: %s' % audience, file=fd)
        print('# Account: %s' % account_server_url, file=fd)
        print('# ------------------------------------', file=fd)
        print('export FXA_BROWSERID_ASSERTION="%s"' % bid_assertion, file=fd)
        print('export FXA_CLIENT_STATE="%s"\n' % client_state, file=fd)

    fd.close()

if __name__ == "__main__":
    main()
