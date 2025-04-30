#!/usr/bin/env python
import argparse
import getpass
import logging
import os
import re
import sys

from fxa.constants import ENVIRONMENT_URLS
from fxa.errors import ClientError
from fxa.tools.create_user import create_new_fxa_account
from fxa.tools.bearer import get_bearer_token
from fxa.tools.unblock import send_unblock_code

DEFAULT_CLIENT_ID = "5882386c6d801776"  # Firefox dev Client ID
DEFAULT_ENV = 'stage'

logger = logging.getLogger("fxa-client")
logging.basicConfig(level=logging.ERROR)


def main(args=None):
    """The main routine."""
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="PyFxA commands")
    parser.add_argument('--bearer',
                        help='Generate a Bearer token',
                        dest='bearer',
                        action='store_true')
    parser.add_argument('--unblock-account',
                        help='Generate an unblock code for the specified email',
                        dest='unblock_account',
                        metavar='EMAIL')

    parser.add_argument('-c', '--create-user',
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
    parser.add_argument('--env',
                        help='The Firefox Account env to use',
                        dest='env',
                        choices=ENVIRONMENT_URLS.keys(),
                        default=DEFAULT_ENV,
                        required=False)

    parser.add_argument('--account-server',
                        help='Firefox Account server URL',
                        dest='account_server_url',
                        required=False)

    parser.add_argument('--oauth-server',
                        help='Firefox Account OAuth server URL',
                        dest='oauth_server_url',
                        required=False)

    parser.add_argument('--client-id',
                        help='Firefox Account OAuth client id.',
                        dest='client_id',
                        required=False,
                        default=DEFAULT_CLIENT_ID)

    parser.add_argument('--client-secret',
                        help='Firefox Account OAuth client secret.',
                        dest='client_secret',
                        required=False)

    parser.add_argument('--use-pkce',
                        help='Whether to use PKCE in OAuth code grant flow.',
                        dest='use_pkce',
                        action='store_true')

    parser.add_argument('--scopes',
                        help='Firefox Account OAuth scopes.',
                        dest='scopes',
                        required=False,
                        default='profile')

    parser.add_argument('--user-email-prefix', '--prefix',
                        help='Firefox Account user creation email prefix.',
                        dest='prefix',
                        required=False,
                        default='fxa')

    parser.add_argument('--unblock-code',
                        help='Use this unblock code when logging in.',
                        metavar='CODE',
                        dest='unblock_code',
                        required=False)

    args = vars(parser.parse_args())
    create = args['create']
    auth = args.get('auth')
    verbose = args['verbose']

    if verbose:
        logger.setLevel(logging.INFO)

    fxa_env = args['env']
    account_server_url = ENVIRONMENT_URLS[fxa_env]['authentication']
    oauth_server_url = ENVIRONMENT_URLS[fxa_env]['oauth']
    content_server_url = ENVIRONMENT_URLS[fxa_env]['content']
    token_server_url = ENVIRONMENT_URLS[fxa_env]['token']

    if args['account_server_url']:
        account_server_url = args['account_server_url']

    if args['oauth_server_url']:
        oauth_server_url = args['oauth_server_url']

    fd = sys.stdout  # By default write to the standard output
    fd_is_to_close = False
    out = args.get('output_file')
    if out:
        out = os.path.abspath(out)
        file_path = os.path.dirname(out)
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        fd = open(out, 'w')
        fd_is_to_close = True

    if args['unblock_account']:
        # Trigger sending an unblock code
        email = args['unblock']

        try:
            send_unblock_code(email, account_server_url)
        except (ClientError, ValueError) as e:
            logger.error(e)
            sys.exit(1)

        logger.info('Unblock code sent')
        sys.exit(0)
    elif auth:
        # Ask for the user password if needed
        auth = auth.split(':', 1)
        if len(auth) < 2:
            email = auth[0]
            password = getpass.getpass('Please enter a password for %s: '
                                       % auth[0])
    elif create:
        # Create a new user
        logger.info('Creating the account.')

        try:
            email, password = create_new_fxa_account(
                os.getenv('FXA_USER_SALT', args.get('fxa_user_salt')),
                account_server_url, args['prefix'], content_server_url)
        except (ClientError, ValueError) as e:
            logger.error(e)
            sys.exit(1)

        logger.info('Account created: %s' % email)

    if args['bearer']:
        # Generate a Bearer Token for the user and write it into a file.
        scopes = [s.strip() for s in re.split(';|,|\t|\n', args['scopes'])
                  if s.strip()]
        client_id = args['client_id']
        unblock_code = args['unblock_code']
        client_secret = args['client_secret']
        use_pkce = args['use_pkce']

        logger.info('Generating the Bearer Token.')

        try:
            token = get_bearer_token(email, password, scopes,
                                     account_server_url,
                                     oauth_server_url,
                                     client_id,
                                     client_secret,
                                     use_pkce,
                                     unblock_code)
        except ClientError as e:
            logger.error(e)
            sys.exit(1)

        logger.info('Bearer Token generated.')

        print('# ---- BEARER TOKEN INFO ----', file=fd)
        print('# User: %s' % email, file=fd)
        print('# Scopes: %s' % ' '.join(scopes), file=fd)
        print('# Account: %s' % account_server_url, file=fd)
        print('# Oauth: %s' % oauth_server_url, file=fd)
        print('# Client ID: %s' % client_id, file=fd)
        print('# ---------------------------', file=fd)
        print('export OAUTH_BEARER_TOKEN="%s"\n' % token, file=fd)

    if fd_is_to_close:
        fd.close()


if __name__ == "__main__":
    main()
