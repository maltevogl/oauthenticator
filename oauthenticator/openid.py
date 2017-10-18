"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json

from base64 import b64decode, b64encode, urlsafe_b64decode
import re

from tornado             import gen, escape
from tornado.auth        import GoogleOAuth2Mixin
from tornado.web         import HTTPError
from tornado.httpclient import HTTPRequest, AsyncHTTPClient


from traitlets           import Unicode, default

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator



from tornado.util import PY3
import functools

if PY3:
    import urllib.parse as urlparse
    import urllib.parse as urllib_parse
    long = int
else:
    import urlparse
    import urllib as urllib_parse

class AuthError(Exception):
    pass

class OpenIDOAuth2Mixin(GoogleOAuth2Mixin):
    """ An OpenID OAuth2 mixin to use GoogleLoginHandler with
    different Identity Providers using the OpenID standard. The current
    setup should work with MITREid Connect servers. In addtion to the usual
    parameters client ID and secret, the environment variable OPENID_HOST
    should be set to the URL of the OpenID provider. The API endpoints
    might have to be changed, depending on the ID provider."""

    CONNECTORS = os.environ.get('CONNECTOR_LIST')

    _OPENID_ENDPOINT = os.environ.get('OPENID_HOST')
    if _OPENID_ENDPOINT.startswith('http'):
        _OAUTH_AUTHORIZE_URL = "%s/auth" % _OPENID_ENDPOINT
        _OAUTH_ACCESS_TOKEN_URL = "%s/token" % _OPENID_ENDPOINT
        _OAUTH_USERINFO_URL = "%s/auth" % _OPENID_ENDPOINT
    else:
        _OAUTH_AUTHORIZE_URL = "https://%s/auth" % _OPENID_ENDPOINT
        _OAUTH_ACCESS_TOKEN_URL = "https://%s/token" % _OPENID_ENDPOINT
        _OAUTH_USERINFO_URL = "https://%s/auth" % _OPENID_ENDPOINT
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'coreos_dex_oauth'


    def get_authenticated_user(self, redirect_uri, code, callback):
        """Handles the login for the Google user, returning an access token.
        """
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })
        #self.log.info('http req body: %r', body)
        #self.log.info('acc tok url: %r', self._OAUTH_ACCESS_TOKEN_URL)
        #self.log.info('callback url: %r', callback)
        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST",
                   headers={'Content-Type': 'application/x-www-form-urlencoded'},
                   body=body,
                   validate_cert = validate_server_cert)


    # def _on_access_token(self, future, response):
    #     """Callback function for the exchange to the access token."""
    #     #self.log.info('response body: %r', response)
    #     if response.error:
    #         future.set_exception(AuthError('OpenID auth error: %s' % str(response)))
    #         return
    #
    #     args = escape.json_decode(response.body)
    #     future.set_result(args)

class OpenIDLoginHandler(OAuthLoginHandler, OpenIDOAuth2Mixin):
    @property
    def scope(self):
        return self.authenticator.scope
    # '''An OAuthLoginHandler that provides scope to GoogleOAuth2Mixin's
    #    authorize_redirect.'''
    # scope=['openid','profile', 'email','offline_access','groups']
    #
    # def get(self):
    #     redirect_uri = self.authenticator.get_callback_url(self)
    #     state = self.get_state()
    #     self.set_state_cookie(state)
    #     self.log.info('OAuth redirect: %r', redirect_uri)
    #     self.authorize_redirect(
    #         redirect_uri=redirect_uri,
    #         client_id=self.authenticator.client_id,
    #         scope=['openid','profile', 'email','offline_access','groups'],
    #         extra_params={'state': state},
    #         response_type='code')


class OpenIDOAuthHandler(OAuthCallbackHandler, OpenIDOAuth2Mixin):
    pass


class OpenIDOAuthenticator(OAuthenticator, OpenIDOAuth2Mixin):
    login_handler = OpenIDLoginHandler
    callback_handler = OpenIDOAuthHandler

    @default('scope')
    def _scope_default(self):
        return ['openid', 'profile', 'email','offline_access','groups']

    login_service =  Unicode(
        os.environ.get('LOGIN_SERVICE', 'Dex'),
        config=True,
        help="""String for button to be displayed to the user before login"""
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument('code')
        handler.settings['coreos_dex_oauth'] = {
            'key': self.client_id,
            'secret': self.client_secret,
            'scope': self.scope,# ['openid','profile', 'email','offline_access','groups'],
            'response_type': 'code'
        }

        validate_server_cert = self.validate_server_cert
        self.log.info('Validate cert: %r', validate_server_cert)

        self.log.info('openid: settings: "%s"', str(handler.settings['coreos_dex_oauth']))
        self.log.info('code is: {}'.format(code))

        user = yield handler.get_authenticated_user(
            redirect_uri=self.get_callback_url(handler),
            code=code)

        access_token = str(user['access_token'])

        self.log.info('token is: {}'.format(access_token))
        self.log.info('full user json is: {}'.format(user))

        #http_client = handler.get_auth_http_client()

        #response = yield http_client.fetch(
        #    self._OAUTH_USERINFO_URL + '?access_token=' + access_token
        #)

        #if not response:
        #    self.clear_all_cookies()
        #    raise HTTPError(500, 'Google authentication failed')

        #body = response.body.decode()
        #self.log.debug('response.body.decode(): {}'.format(body))
        #bodyjs = json.loads(body)
        payload_encoded = user['id_token'].split('.')[1]
        payload = urlsafe_b64decode(payload_encoded + '=' * (4 - len(payload_encoded) % 4)).decode('utf8')
        self.log.info('urlsafe decoded payload is: {}'.format(payload))
        userstring = re.findall('(?<=sub":").+?(?=",)',payload)[0]
        substring = urlsafe_b64decode(userstring + '=' * (4 - len(userstring) % 4)).decode('utf8')

        substring_print = ''.join([i for i in substring if i.isprintable()])
        self.log.info('urlsafe decoded, printable substring is: {}'.format(substring_print))

        username = ''

        for connector in self.CONNECTORS.split(','):
            if connector == 'github':
                if re.findall('(?<=name":").+?(?=")', payload):
                    returned_name = re.findall('(?<=name":").+?(?=")', payload)[0]
                    username = re.sub(' ','',returned_name) + '_' + 'github'
                else:
                    pass
            elif re.findall(connector,substring_print):
                username = re.sub(connector,'_' + connector,substring_print)
            else:
                pass

        if not username:
            raise Exception('Connector error: Could not extract username from id_token, sub or name entry.')

        #if self.hosted_domain:
        #    if not username.endswith('@'+self.hosted_domain) or \
        #        bodyjs['hd'] != self.hosted_domain:
        #        raise HTTPError(403,
        #            "You are not signed in to your {} account.".format(
        #                self.hosted_domain)
        #        )
        #    else:
        #        username = username.split('@')[0]

        return username

class LocalOpenIDOAuthenticator(LocalAuthenticator, OpenIDOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
