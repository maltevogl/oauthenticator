from unittest.mock import Mock

from pytest import fixture, mark, raises
from tornado.web import Application, HTTPError

from ..openid import OpenIDOAuthenticator, OpenIDOAuthHandler

from .mocks import setup_oauth_mock

def user_model(email):
    """Return a user model"""
    return {
        'email': email,
        'hd': email.split('@')[1],
    }

@fixture
def openid_client(client):
    setup_oauth_mock(client,
        host=['www.openid.com'],
        access_token_path='/token',
        user_path='/oauth2/v1/userinfo',
    )
    original_handler_for_user = client.handler_for_user
    # testing Google is harder because it invokes methods inherited from tornado
    # classes
    def handler_for_user(user):
        mock_handler = original_handler_for_user(user)
        mock_handler.request.connection = Mock()
        real_handler = OpenIDOAuthHandler(
            application=Application(hub=mock_handler.hub),
            request=mock_handler.request,
        )
        return real_handler
    client.handler_for_user = handler_for_user
    return client


@mark.gen_test
def test_openid(openid_client):
    authenticator = OpenIDOAuthenticator()
    handler = openid_client.handler_for_user(user_model('fake@openid.com'))
    name = yield authenticator.authenticate(handler)
    assert name == 'fake@openid.com'
