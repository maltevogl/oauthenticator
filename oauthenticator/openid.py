"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json

from base64 import b64decode
import re
import jwt

from tornado             import gen, escape
from tornado.auth        import GoogleOAuth2Mixin
from tornado.web         import HTTPError

from traitlets           import Unicode

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator


## debug only ##
from tornado.util import unicode_type, ArgReplacer, PY3
from tornado.concurrent import TracebackFuture, return_future, chain_future
import functools
from tornado.stack_context import ExceptionStackContext

if PY3:
    import urllib.parse as urlparse
    import urllib.parse as urllib_parse
    long = int
else:
    import urlparse
    import urllib as urllib_parse


class AuthError(Exception):
    pass


def _auth_future_to_callback(callback, future):
    try:
        result = future.result()
    except AuthError as e:
        gen_log.warning(str(e))
        result = None
    callback(result)

def _auth_return_future(f):
    """Similar to tornado.concurrent.return_future, but uses the auth
    module's legacy callback interface.

    Note that when using this decorator the ``callback`` parameter
    inside the function will actually be a future.
    """
    replacer = ArgReplacer(f, 'callback')

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        future = TracebackFuture()
        callback, args, kwargs = replacer.replace(future, args, kwargs)
        if callback is not None:
            future.add_done_callback(
                functools.partial(_auth_future_to_callback, callback))

        def handle_exception(typ, value, tb):
            if future.done():
                return False
            else:
                future.set_exc_info((typ, value, tb))
                return True
        with ExceptionStackContext(handle_exception):
            f(*args, **kwargs)
        return future
    return wrapper
#################

class OpenIDOAuth2Mixin(GoogleOAuth2Mixin):
    """ An OpenID OAuth2 mixin to use GoogleLoginHandler with
    different Identity Providers using the OpenID standard. The current
    setup should work with MITREid Connect servers. In addtion to the usual
    parameters client ID and secret, the environment variable OPENID_HOST
    should be set to the URL of the OpenID provider. The API endpoints
    might have to be changed, depending on the ID provider."""
    _OPENID_ENDPOINT = os.environ.get('OPENID_HOST')
    OPENID_HOST=_OPENID_ENDPOINT
    _OAUTH_AUTHORIZE_URL = "http://%s/auth" % OPENID_HOST
    _OAUTH_ACCESS_TOKEN_URL = "http://%s/token" % OPENID_HOST
    _OAUTH_USERINFO_URL = "http://%s/auth" % OPENID_HOST

    @_auth_return_future
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
        self.log.info('http req body: %r', body)
        self.log.info('acc tok url: %r', self._OAUTH_ACCESS_TOKEN_URL)
        self.log.info('callback url: %r', callback)
        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)


    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        self.log.info('response body: %r', response)
        if response.error:
            future.set_exception(AuthError('OpenID auth error: %s' % str(response)))
            return

        args = escape.json_decode(response.body)
        future.set_result(args)

class OpenIDLoginHandler(OAuthLoginHandler, OpenIDOAuth2Mixin):
    '''An OAuthLoginHandler that provides scope to GoogleOAuth2Mixin's
       authorize_redirect.'''
    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('redirect_uri: %r', redirect_uri)

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=['openid','profile', 'email'],
            response_type='id_token')


class OpenIDOAuthHandler(OAuthCallbackHandler, OpenIDOAuth2Mixin):
    pass


class OpenIDOAuthenticator(OAuthenticator, OpenIDOAuth2Mixin):

    login_handler = OpenIDLoginHandler
    callback_handler = OpenIDOAuthHandler

    hosted_domain = Unicode(
        os.environ.get('HOSTED_DOMAIN', ''),
        config=True,
        help="""Hosted domain used to restrict sign-in, e.g. mycollege.edu"""
    )
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Google'),
        config=True,
        help="""Google Apps hosted domain string, e.g. My College"""
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument('code', False)
        if not code:
            raise HTTPError(400, "oauth callback made without a token")
        handler.settings['google_oauth'] = {
            'key': self.client_id,
            'secret': self.client_secret,
            'scope': ['openid','profile', 'email'],
            'claims': ['user_id','name']
        }
        self.log.debug('openid: settings: "%s"', str(handler.settings['google_oauth']))
        self.log.debug('code is: {}'.format(code))
        user = yield handler.get_authenticated_user(
            redirect_uri=self.get_callback_url(handler),
            code=code)
        access_token = str(user['access_token'])
        self.log.debug('token is: {}'.format(access_token))
        self.log.debug('full user json is: {}'.format(user))

        http_client = handler.get_auth_http_client()

        #response = yield http_client.fetch(
        #    self._OAUTH_USERINFO_URL + '?access_token=' + access_token
        #)

        #if not response:
        #    self.clear_all_cookies()
        #    raise HTTPError(500, 'Google authentication failed')

        #body = response.body.decode()
        #self.log.debug('response.body.decode(): {}'.format(body))
        #bodyjs = json.loads(body)
        payload = jwt.decode(user['id_token'],verify=False)
        self.log.debug('decoded payload is: {}'.format(payload))
        username = payload['sub']

        if self.hosted_domain:
            if not username.endswith('@'+self.hosted_domain) or \
                bodyjs['hd'] != self.hosted_domain:
                raise HTTPError(403,
                    "You are not signed in to your {} account.".format(
                        self.hosted_domain)
                )
            else:
                username = username.split('@')[0]

        return username

class LocalOpenIDOAuthenticator(LocalAuthenticator, OpenIDOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
