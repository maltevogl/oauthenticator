"""
Custom Authenticator to use Google OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from base64 import b64decode, b64encode, urlsafe_b64decode
import re
from subprocess import check_call

from tornado             import gen, escape
from tornado.auth        import GoogleOAuth2Mixin
from tornado.web         import HTTPError
#from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from tornado.concurrent import TracebackFuture, return_future, chain_future
from tornado.log import gen_log
from tornado.stack_context import ExceptionStackContext


from traitlets           import Unicode, default

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator



from tornado.util import PY3, ArgReplacer, unicode_type
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


class OpenIDOAuth2Mixin(GoogleOAuth2Mixin):
    """ An OpenID OAuth2 mixin to use GoogleLoginHandler with
    different Identity Providers using the OpenID standard. The current
    setup should work with MITREid Connect servers. In addtion to the usual
    parameters client ID and secret, the environment variable OPENID_HOST
    should be set to the URL of the OpenID provider. The API endpoints
    might have to be changed, depending on the ID provider."""

    def __init__(self):
        with open('/srv/jupyterhub/api_token.txt') as file:
            user_api_token = file.readline().rstrip('\n')
        self.log.info('Got token: {0}'.format(user_api_token))
        sessions = requests.Session()
        retry = Retry(connect=5, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        header = {'Authorization': 'token {0}'.format(user_api_token)}
        session.get('https://c105-188.cloud.gwdg.de:442/hub/api/users',
            headers=header
            )
        self.log.info('request get send')
        r.raise_for_status()
        userdicts = r.json()
        self.userlist = [user['name'] for user in userdicts]


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


    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback,validate_server_cert):
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
                   method="POST",
                   headers={'Content-Type': 'application/x-www-form-urlencoded'},
                   body=body,
                   validate_cert = validate_server_cert)


    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        #self.log.info('response body: %r', response)
        if response.error:
            future.set_exception(AuthError('OpenID auth error: %s' % str(response)))
            return

        args = escape.json_decode(response.body)
        future.set_result(args)

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
        self.log.info('openid settings: "%s"', str(handler.settings['coreos_dex_oauth']))
        #self.log.info('code is: {}'.format(code))

        user = yield handler.get_authenticated_user(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            validate_server_cert=validate_server_cert)

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
        ###
        # TODO: Fix to make portable
        ###

        for connector in self.CONNECTORS.split(','):
            try:
                if substring_print.endswith(connector):
                    returned_name = re.findall('(?<=name":").+?(?=")', payload)
                    if returned_name:
                        username = re.sub(' ','',returned_name[0]).lower() + '_' + connector
                    else:
                        username = re.sub(connector,'',substring_print).lower() + '_' + connector
                else:
                    self.log.info('Could not find {0} in {1}.'.format(connector,substring_print))
                    pass
            except:
                self.log.info('Try failed for {0} in {1}.'.format(connector,substring_print))
                pass

        if username:
            self.log.info('Working on user {0}'.format(username))
            if username.split('_')[-1] == 'saml':
                self.log.info('\tis saml user.')
                self.log.info('Existing users: {0}'.format(self.userlist))
                if username not in self.userlist:
                    try:
                        self.log.info('Try adding user to db.')
                        res0 = check_call(['echo',username,'>>', '/srv/jupyterhub/userlist.txt'])
                        userNameFilePath = '/srv/jupyterhub/userfiles/' + username + '.txt'
                        res1 = check_call(['echo',username,'>',userNameFilePath])
                        res2 = check_call(['/srv/jupyterhub/add_users.sh',userNameFilePath])
                    except:
                        self.log.info('Could not add user {0}.'.format(username))
                        pass
                else:
                    pass
            else:
                pass
        else:
            self.log.info('Connector error: Could not extract username from id_token, sub or name entry.')
        return username

class LocalOpenIDOAuthenticator(LocalAuthenticator, OpenIDOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
