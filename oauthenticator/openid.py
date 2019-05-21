"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""
######
# packages for jupyter setup
from base64 import urlsafe_b64decode
import re
import ast
from subprocess import check_output
######

import json
import os
import base64
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict, Bool

from .oauth2 import OAuthLoginHandler, OAuthenticator


class OpenIDEnvMixin(OAuth2Mixin):

    _OAUTH_ACCESS_TOKEN_URL = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        help="OpenID Connect endpoint for access token",
        config=True
    )

    _OAUTH_AUTHORIZE_URL = Unicode(
        os.environ.get('OAUTH2_AUTHORIZE_URL', ''),
        help="OpenID Connect enpoint for authorization",
        config=True
    )

class OpenIDLoginHandler(OAuthLoginHandler, OpenIDEnvMixin):
    @property
    def scope(self):
        return self.authenticator.scope
    pass


class OpenIDOAuthenticator(OAuthenticator, OpenIDEnvMixin):

    login_handler = OpenIDLoginHandler

    scope =  ['openid', 'profile', 'email', 'groups']

    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'dex'),
        config=True,
        help="String to be displayed in Login-Button"
    )

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )
    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Access token endpoint URL"
    )
    extra_params = Dict(
        os.environ.get('OAUTH2_AUTHENTICATION_PARAMS', {}),
        help="Extra parameters for first POST request"
    ).tag(config=True)

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = {'scope':['openid','profile','email']}
    #Dict(
    #    os.environ.get('OAUTH2_USERDATA_PARAMS', {}),
    #    help="Userdata params to get user data login information"
    #).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request"
    )

    connectors = Unicode(
        os.environ.get('CONNECTOR_LIST','').split(','),
        config=True,
        help="List of allowed IDP endpoints"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):

        if connectors != ['']:
            pass
        else:
            raise ValueError("Please specify the CONNECTOR_LIST environment variable")

        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        id_token = resp_json.get('id_token', None)
        token_type = resp_json['token_type']
        scope = (resp_json.get('scope', '')).split(' ')

        # Get userinfo from id_token
        if not id_token:
            self.log.error("Could not read id_token from response: %s", resp_json)
            return
        payload_encoded = id_token.split('.')[1]
        payload = urlsafe_b64decode(
            payload_encoded + '=' * (4 - len(payload_encoded) % 4)
            ).decode('utf8')
        self.log.info(
            'urlsafe decoded payload is: {}'.format(
                payload
                )
            )

        userstring = re.findall('(?<=sub":").+?(?=",)', payload)[0]
        substring = urlsafe_b64decode(
            userstring + '=' * (4 - len(userstring) % 4)
            ).decode('utf8')

        substring_print = ''.join([i for i in substring if i.isprintable()])
        self.log.info(
            'urlsafe decoded, printable substring is: {}'.format(
                substring_print
                )
            )

        username = ''
        ###
        # TODO: Fix to make portable
        ###

        for connector in connectors:
            try:
                if substring_print.endswith(connector):
                    try:
                        payloadString = re.sub('false', 'False', re.sub('true', 'True', payload))
                        idDict = ast.literal_eval(payloadString)
                        returned_name = idDict['name']
                        returned_email = idDict['email']
                    except:
                        self.log.info('Could not get id token dict.')
                        returned_name = re.findall('(?<=name":").+?(?=")', payload)
                        returned_email = re.findall('(?<=email":").+?(?=")', payload)
                    if returned_name:
                        if type(returned_name) == list:
                            returned_name = returned_name[0]
                        username = re.sub(' ', '', returned_name).lower() + '_' + connector
                    else:
                        username = re.sub(connector, '', substring_print).lower() + '_' + connector
                    break
                else:
                    self.log.info(
                        'Could not find {0} in {1}.'.format(
                            connector, substring_print
                            )
                        )
            except ValueError:
                self.log.info(
                    'Try failed for {0} in {1}.'.format(
                        connector, substring_print
                        )
                    )

        if username:
            charSet = {'ü': 'ue', 'ä': 'ae', 'ö': 'oe', 'ß': 'ss'}
            for key, value in charSet.items():
                username = re.sub(key, value, username)
            self.log.info('Working on user {0}'.format(username))
            usergroup = username.split('_')[-1]
            if usergroup in connectors:
                self.log.info('\tis {0} user.'.format(usergroup))
                with open('/srv/jupyterhub/userlist.txt') as file:
                    userlist = [x.split(' ')[0] for x in file.read().split('\n')]
                self.log.info('Existing users: {0}'.format(userlist))
                if username not in userlist:
                    try:
                        self.log.info('Try adding user to db.')
                        userNameFilePath = '/srv/jupyterhub/userfiles/{0}.txt'.format(username)
                        check_output(
                            'echo {0} {1} {2} > {3}'.format(username, usergroup, returned_email, userNameFilePath),
                            shell=True
                            )
                    except IOError:
                        self.log.info(
                            'Could not write {} to file.'.format(username)
                            )
                    try:
                        check_output(
                            '/srv/jupyterhub/add_users.sh {0}'.format(
                                userNameFilePath
                                ),
                            shell=True
                            )
                    except RuntimeError:
                        self.log.info(
                            'Could not run adduser script for {0}.'.format(
                                username
                                )
                            )
                        username = ''
                else:
                    pass
            else:
                self.log.info(
                    'User group {0} not in connector list {1}.'.format(
                        usergroup, connectors
                        )
                    )
                pass
        else:
            self.log.info(
                'Connector error: Could not extract username from id_token,\
                sub or name entry.'
                )

        return {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'id_token': id_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }


class LocalOpenIDOAuthenticator(LocalAuthenticator, OpenIDOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
