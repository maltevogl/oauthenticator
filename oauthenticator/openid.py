"""
Custom Authenticator to use OpenID OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator, based on GoogleOAuthHandler.
"""

import os
import json

from tornado             import gen
from tornado.auth        import OpenIdMixin
from tornado.web         import HTTPError

from traitlets           import Unicode

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator


class OpenIDOAuth2Mixin(OpenIdMixin):
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
    _OAUTH_USERINFO_URL = "http://%s/token" % OPENID_HOST


class OpenIDLoginHandler(OAuthLoginHandler, OpenIDOAuth2Mixin):
    '''An OAuthLoginHandler that provides scope to GoogleOAuth2Mixin's
       authorize_redirect.'''
    def get(self):
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )

        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('redirect_uri: %r', redirect_uri)

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=['openid', 'email'],
            response_type='code')

class OpenIDOAuthHandler(OAuthCallbackHandler, OpenIDOAuth2Mixin):

    @gen.coroutine
    def get(self):
        self.settings['google_oauth'] = {
            'key': self.authenticator.client_id,
            'secret': self.authenticator.client_secret,
            'scope': ['openid', 'email']
        }
        #self.log.debug('openid: settings: "%s"', str(self.settings['google_oauth']))

        # "Cannot redirect after headers have been written" ?
        #OAuthCallbackHandler.get(self)
        username = yield self.authenticator.get_authenticated_user(self, None)
        self.log.info('openid: username: "%s"', username)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error
            raise HTTPError(403)

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
        if not self.oauth_callback_url:
            raise HTTPError(500, "No callback URL")
        user = yield handler.get_authenticated_user(
            redirect_uri=self.oauth_callback_url,
            code=code)
        access_token = str(user['access_token'])

        http_client = handler.get_auth_http_client()

        response = yield http_client.fetch(
            self._OAUTH_USERINFO_URL + '?access_token=' + access_token
        )

        if not response:
            self.clear_all_cookies()
            raise HTTPError(500, 'Google authentication failed')

        body = response.body.decode()
        self.log.debug('response.body.decode(): {}'.format(body))
        bodyjs = json.loads(body)

        username = bodyjs['sub']

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
