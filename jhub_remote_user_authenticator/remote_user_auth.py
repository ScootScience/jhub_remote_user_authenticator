
import os
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode


class RemoteUserLoginHandler(BaseHandler):

    def get(self):
        self.log.debug("RemoteUserLoginHandler: get() called, login request made")
        header_name = self.authenticator.header_name
        remote_user = self.request.headers.get(header_name, "")
        self.log.debug("Call is for user %s via header %s" % (remote_user, header_name))
        if remote_user == "":
            raise web.HTTPError(401)

        user = self.user_from_username(remote_user)
        self.log.debug("Using username %s, fetched DB user %s" % (remote_user, user))
        self.clear_login_cookie()
        self.set_login_cookie(user)
        next_url = self.get_next_url(user)
        self.log.debug("Reset login cookie; redirecting to %s" % next_url)
        self.redirect(next_url)


class RemoteUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class RemoteUserLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
