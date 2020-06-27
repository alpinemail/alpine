#!/usr/bin/python3
#
# Copyright 2020, Eduardo Chappa <eduardo.chappa@gmx.com>
# Based on the oauth2.py script Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This script can be used to obtain the initial refresh token and access token
for an app, or to renew an access token, and in both cases obtain the encoded
base64 encoded string that is used to add to an authorization command in an
IMAP or SMTP server.

 * In order to get the initial refresh token and access token, determine the tenant
   you will use. The default is 'common'. You also need to supply the client-id of
   your app.

   ooauth2  [--tenant=common] --client_id=f21d...  --generate_refresh_and_access_token

   The script will give you a url and a code. Open the url with a browser and enter
   the code where requested. You will be redirected to login with your username
   and password. After a succesful login, you will be asked to authorize
   the app. Once you have authorized the app, close that window and return to
   this script. Press "ENTER" and you will see your refresh-token, access-token
   and total amount of time (in seconds) that your token is valid. This is typically
   3600 seconds (one hour). Please note that the refresh token and access token are
   very long strings, each one them should be saved in a file one line long each.

 * You can also use this script to generate a new access_token. In order to do this
   you need the tenant, the client-id, and a refresh-token. Then you would run this
   script as

   ooauth2 [--tenant=common] --client_id=f21d... --refresh_token=MCRagxlHaZfUvV9kG0lnBk...

   as an advice copy and paste the refresh token that you were given into a file,
   and replace the command line option
      --refresh_token=MCRagxlHaZfUvV9kG0lnBk...
   by
      --refresh_token=`cat filename`

 * The last way to use this script is to use the previous commands, but add
   --encoded to any of the previous commands. This will produce a base64 string that
   can be added to an IMAP "AUTHENTICATE XOAUTH2" command, or an "AUTH XOAUTH2" SMTP
   command, to login to that server. The access token will not be displayed, only
   the encoded base64 string. If you use this option, you must also provide
   the --user option. For example:

    ooauth2  [--tenant=common] --client_id=f21d... --generate_refresh_and_access_token \
    --encoded --user=YourID@outlook.com

   or

   ooauth2 [--tenant=common] --client_id=f21d... --refresh_token=MCRagxlHaZfUvV9kG0lnBk...
   --encoded --user=YourID@outlook.com
"""

import base64
import json
from optparse import OptionParser
import sys
import urllib.request, urllib.parse, urllib.error

# The URL root for authorizations (device code, refresh token and access token)
MICROSOFT_BASE_URL = 'https://login.microsoftonline.com'

# Default grant type
GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'

# Default scope to access IMAP and SMTP.
SCOPE = 'offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send'

def SetupOptionParser():
  # Usage message is the module's docstring.
  parser = OptionParser(usage=__doc__)
  parser.add_option('--generate_refresh_and_access_token',
                    action='store_true',
                    dest='generate_refresh_and_access_token',
                    help='generates an OAuth2 token for testing')
  parser.add_option('--generate_access_token',
                    action='store_true',
                    dest='generate_access_token',
                    help='generates an initial client response string for '
                         'OAuth2')
  parser.add_option('--user',
		    default=None,
                    help='your username. Only needed if --encoded is needed')
  parser.add_option('--encoded',
                    action='store_true',
                    default=False,
                    dest='encoded',
                    help='returns a base64 encoded string, ready to add to your authentication request')
  parser.add_option('--client_id',
                    default=None,
                    help='Client ID of the application that is authenticating. '
                         'See OAuth2 documentation for details.')
  parser.add_option('--tenant',
                    default='common',
                    help='Use a specific tenant. Default: common')
  parser.add_option('--scope',
                    default=SCOPE,
                    help='scope for the access token. Multiple scopes can be '
                         'listed separated by spaces with the whole argument '
                         'quoted.')
  parser.add_option('--access_token',
                    default=None,
                    help='OAuth2 access token')
  parser.add_option('--refresh_token',
                    default=None,
                    help='OAuth2 refresh token')
  return parser

def AccountsUrl(tenant, command):
  return '%s/%s/%s' % (MICROSOFT_BASE_URL, tenant, command)

def UrlEscape(text):
  return urllib.parse.quote(text, safe='~-._')

def UrlUnescape(text):
  return urllib.parse.unquote(text)

def FormatUrlParams(params):
  param_fragments = []
  for param in sorted(iter(params.items()), key=lambda x: x[0]):
    param_fragments.append('%s=%s' % (param[0], UrlEscape(param[1])))
  return '&'.join(param_fragments)

def GeneratePermissionUrl(tenant, client_id, scope=SCOPE):
  params = {}
  params['client_id'] = client_id
  params['scope'] = scope
  request_url = AccountsUrl(tenant, 'oauth2/v2.0/devicecode')
  response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode()).read()
  return json.loads(response)

def AuthorizeTokens(tenant, client_id, DeviceCode):
  params = {}
  params['client_id'] = client_id
  params['device_code'] = DeviceCode
  params['grant_type'] = GRANT_TYPE
  request_url = AccountsUrl(tenant, 'oauth2/v2.0/token')
  response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode()).read()
  return json.loads(response)

def GenerateAccessToken(tenant, client_id, refresh_token, scope=SCOPE):
  params = {}
  params['client_id'] = client_id
  params['refresh_token'] = refresh_token
  params['grant_type'] = scope
  params['grant_type'] = 'refresh_token'
  request_url = AccountsUrl(tenant, 'oauth2/v2.0/token')
  response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params)).read()
  return json.loads(response)['access_token']

def Oauth2EncodedString(user, access_token):
  rawstring = 'user=%s\1auth=Bearer %s\1\1' % (user, access_token)
  return base64.b64encode(str.encode(rawstring)).decode()

def RequireOptions(options, *args):
  missing = [arg for arg in args if getattr(options, arg) is None]
  if missing:
    print('Missing options: %s' % ' '.join(missing))
    sys.exit(-1)

def main(argv):
  options_parser = SetupOptionParser()
  (options, args) = options_parser.parse_args()
  if options.generate_access_token:
    RequireOptions(options, 'tenant', 'refresh_token')
    access_token = GenerateAccessToken(options.tenant, options.client_id, options.refresh_token, options.scope)
    if options.encoded:
        RequireOptions(options, 'user')
        print('%s' % Oauth2EncodedString(options.user, access_token))
    else:
        print('%s' % access_token)
  elif options.generate_refresh_and_access_token:
    RequireOptions(options, 'tenant', 'client_id')
    response = GeneratePermissionUrl(options.tenant, options.client_id, options.scope)
    print('%s' % response['message'])
    input('Go to the URL above, complete the authorizaion process, and press ENTER when you are done')
    response = AuthorizeTokens(options.tenant, options.client_id, response['device_code'])
    print('Refresh Token: %s' % response['refresh_token'])
    if options.encoded:
        RequireOptions(options, 'user')
        print('%s' % Oauth2EncodedString(options.user, response['access_token']))
    else:
        print('Access Token: %s' % response['access_token'])
    print('Access Token Expiration Seconds: %s' % response['expires_in'])
  else:
    options_parser.print_help()
    print('Nothing to do, exiting.')
    return

if __name__ == '__main__':
  main(sys.argv)
