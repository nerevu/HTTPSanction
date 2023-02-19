# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from pathlib import Path

import pygogo as gogo

from attr import dataclass, field
from flask import (
    current_app as app,
    has_app_context,
    redirect,
    request,
    session,
    url_for,
)
from meza.fntools import remove_keys

from app import LOG_LEVELS, cache
from app.authclient import AuthClientTypes, callback, get_auth_client
from app.helpers import flask_formatter as formatter, get_verbosity
from app.providers import Authentication
from app.routes import PatchedMethodView
from app.utils import extract_fields, jsonify, parse_item

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

APP_DIR = Path(__file__).parents[1]
DATA_DIR = APP_DIR.joinpath("data")


@dataclass
class BaseView(PatchedMethodView):
    auth: Authentication = field(default=None, kw_only=True, repr=False)
    methods: list[str] = field(factory=list, kw_only=True, repr=False)
    client: AuthClientTypes = field(init=False, repr=False)

    def __attrs_post_init__(self, **kwargs):
        super().__attrs_post_init__()
        self.methods = self.methods or ["GET"]
        self.verbosity = get_verbosity(**kwargs)
        logger.setLevel(LOG_LEVELS.get(self.verbosity))

        api_url = kwargs.get("API_URL")

        if has_app_context():
            args = (self.prefix, self.auth)
            self.client = get_auth_client(*args, **app.config, **kwargs)


class Callback(BaseView):
    def get(self):
        return callback(self.prefix, self.auth)


class Auth(BaseView):
    def get(self):
        """Authenticate User.

        Redirect the user owner to the OAuth provider (i.e. Github)
        using a URL with a few key OAuth parameters.
        """
        authorization_url = None
        result = jsonify()
        cache.set(f"{self.prefix}_callback_url", request.args.get("callback_url"))
        client = self.client

        try:
            # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
            # State is used to prevent CSRF, keep this for later.
            authorization_url, state = client.authorization_url
        except AttributeError:
            pass
        else:
            client.state = session[f"{self.prefix}_state"] = state
            client.save()

        if client.verified and not client.expired:
            json = {k: getattr(client, k) for k in ["token", "state", "realm_id"]}
            result = jsonify(**json)
        else:
            if client.oauth1:
                # clear previously cached token
                client.renew_token()
                authorization_url = client.authorization_url[0]

            if authorization_url:
                logger.info("redirecting to %s", authorization_url)
                result = redirect(authorization_url)

        return result

    def patch(self):
        self.client.renew_token()
        return redirect(url_for(f".{self.prefix}-auth".lower()))

    def delete(self, base=None):
        # TODO: find out where this was implemented
        json = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**json)
