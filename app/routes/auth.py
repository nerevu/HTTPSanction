# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from datetime import datetime as dt, timedelta

from pathlib import Path
from urllib.parse import unquote

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

from app import LOG_LEVELS, cache
from app.authclient import (
    FLOW_TYPES,
    AuthClientTypes,
    callback,
    get_auth_client,
    get_json_response,
)

from app.helpers import flask_formatter as formatter, get_verbosity
from app.providers import Authentication
from app.route_helpers import get_status_resource
from app.routes import PatchedMethodView

from app.utils import extract_field, jsonify

try:
    from app.providers import Provider, Resource
except ImportError:
    Resource = Provider = None

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False

APP_DIR = Path(__file__).parents[1]
DATA_DIR = APP_DIR.joinpath("data")
HEADERS = {"Accept": "application/json"}


def get_resource_url(resource: Resource, auth: Authentication):
    url = f"{auth.api_base_url}/{resource.resource_name}"

    if resource.subresource and resource.rid:
        url += f"/{resource.rid}/{resource.subresource}"
    elif resource.subresource:
        breakpoint()

    if auth.api_ext:
        url += f".{auth.api_ext}"

    # Some APIs urls (like mailgun) have a section that may or may not be present
    return url.replace("/None", "")


@dataclass
class BaseView(PatchedMethodView):
    auth: Authentication = field(default=None, kw_only=True, repr=False)
    resource: Resource = field(default=None, kw_only=True, repr=False)
    provider: Provider = field(default=None, kw_only=True, repr=False)
    methods: list[str] = field(factory=list, kw_only=True, repr=False)
    client: AuthClientTypes = field(init=False, repr=False)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        kwargs = {
            "verbosity": app.config["VERBOSITY"],
            "debug": self.auth.debug,
            **app.config,
        }
        self.methods = self.methods or ["GET"]
        self.verbosity = get_verbosity(**kwargs)
        logger.setLevel(LOG_LEVELS.get(self.verbosity))

        if not self.auth.auth_id:
            self.auth.auth_id = self.auth.auth_type
        elif not self.auth.auth_type:
            self.auth.auth_type = self.auth.auth_id

        if not self.auth.refresh_url:
            self.auth.refresh_url = self.auth.token_url

        if not self.auth.redirect_uri:
            self.auth.redirect_uri = f"/{self.prefix}-callback"

        if not self.auth.flow_type:
            self.auth.flow_type = "web"

        if not self.auth.extractions:
            self.auth.extractions = {}

        if not self.auth.params:
            self.auth.params = {}

        api_url = kwargs.get("API_URL").format(app.config["PORT"], **kwargs)

        if self.auth.redirect_uri.startswith("/") and api_url:
            self.auth.redirect_uri = f"{api_url}{self.auth.redirect_uri}"

        if self.auth.flow_type in FLOW_TYPES and self.auth.auth_type == "oauth2":
            self.auth.auth_type = f"oauth2{self.auth.flow_type}"
            self.auth.flow_enum = FLOW_TYPES.get(self.auth.flow_type)

        if self.provider and not self.provider.status_resource_id:
            self.provider.status_resource_id = "status"

        if self.provider and self.provider.resources:
            if resource := get_status_resource(self.provider):
                self.provider.status_resource = resource
            else:
                rid = self.provider.status_resource_id
                logger.error(f"No resource with resourceId {rid} found.")
                breakpoint()

        if has_app_context():
            args = (self.prefix, self.auth)
            self.client = get_auth_client(*args, **kwargs)


class Callback(BaseView):
    def get(self):
        return callback(self.prefix, self.auth)


class Auth(BaseView):
    @property
    def id(self):
        if self.resource:
            _id = self.resource.srid if self.resource.subresource else self.resource.rid
        else:
            _id = None

        return _id

    @property
    def _params(self):
        params = {}

        if self.id:
            id_param = self.auth.param_map.id or "id"
            params[id_param] = self.id

        if self.resource:
            params.update(self.resource.params or {})

            if self.resource.fields:
                fields_param = self.auth.param_map.fields or "fields"
                params[fields_param] = ",".join(self.resource.fields)

            if self.resource.start:
                start_param = self.auth.param_map.start or "start"
                params[start_param] = self.resource.start

            if self.resource.end:
                end_param = self.auth.param_map.end or "end"
                params[end_param] = self.resource.end

        return params

    @property
    def params(self):
        params = {**self.auth.params, **self._params}

        if self.resource:
            params.update(**self.resource.params or {})

        return params

    def get_headers(self, method: str = "GET", **kwargs):
        if self.auth.headers:
            auth_all_headers = self.auth.headers.all or {}
            auth_method_headers = getattr(self.auth.headers, method, {})
            auth_headers = {**auth_all_headers, **auth_method_headers}
        else:
            auth_headers = {}

        if self.resource and self.resource.headers:
            resource_all_headers = self.resource.headers.all or {}
            resource_method_headers = getattr(self.resource.headers, method, {})
            resource_headers = {**resource_all_headers, **resource_method_headers}
        else:
            resource_headers = {}

        return {**HEADERS, **auth_headers, **resource_headers}

    def get_json_response(self, url, **kwargs):
        headers = self.get_headers(**kwargs)
        return get_json_response(
            url, self.client, headers=headers, params=self.params, **kwargs
        )

    def get(self):
        """Authenticate User.

        Redirect the user owner to the OAuth provider (i.e. Github)
        using a URL with a few key OAuth parameters.
        """
        cache.set(f"{self.prefix}_callback_url", request.args.get("callback_url"))
        authorization_url = None
        json = {"description": "Authenticates a user"}

        try:
            # https://gist.github.com/ib-lundgren/6507798#gistcomment-1006218
            # State is used to prevent CSRF, keep this for later.
            authorization_url, state = self.client.authorization_and_state
        except AttributeError:
            pass
        else:
            self.client.state = session[f"{self.prefix}_state"] = state
            self.client.save()

        if self.client.verified and not self.client.expired:
            if self.provider.status_resource:
                url = get_resource_url(self.provider.status_resource, self.auth)
                status = self.get_json_response(url)
                json.update(**status)

            for k in ["token", "state", "realm_id"]:
                try:
                    value = getattr(self.client, k)
                except AttributeError:
                    value = None

                json.update({k: value})

            for key, path in self.auth.extractions.items():
                value = extract_field(json, path)

                if value:
                    self.auth.attrs = self.auth.attrs or {}
                    self.auth.attrs[key] = json[key] = value
                    self.client.save()
                    logger.debug(f"Set {self.client} {key} to {value}.")
                else:
                    self.client.error = f"path `{path}` not found in json!"

            result = jsonify(**json)
        else:
            logger.info("Attempting to re-authenticate")

            if self.client.oauth1:
                # clear previously cached token
                self.client.renew_token()
                authorization_url = self.client.authorization_url

            if authorization_url:
                url = unquote(authorization_url)
                logger.info("redirecting to %s", url)
                result = redirect(url)
            else:
                result = jsonify(**json)

        return result

    def patch(self):
        self.client.renew_token()
        return redirect(url_for(f".{self.prefix}-auth".lower()))

    def delete(self, base=None):
        # TODO: find out where this was implemented
        json = {"status_code": 200, "message": self.client.revoke_token()}
        return jsonify(**json)


class APIResource(BaseView):
    """An API Resource."""

    def __attrs_post_init__(self, *args, **kwargs):
        super().__attrs_post_init__()

        if not self.resource.id_field:
            try:
                self.resource.id_field = next(
                    f
                    for f in self.resource.fields
                    if f.lower().endswith("_id") or f.endswith("Id")
                )
            except StopIteration:
                self.resource.id_field = "id"

        if not self.resource.name_field:
            try:
                self.resource.name_field = next(
                    f for f in self.resource.fields if f.lower().endswith("name")
                )
            except StopIteration:
                self.resource.name_field = "name"

        if not self.resource.start:
            self.resource.start = dt.strptime(
                self.resource.end, (self.resource.datefmt)
            ) - timedelta(days=self.resource.days)

    @property
    def lowered_resource(self):
        return self.resource.resource_name.lower()

    @property
    def lowered_subresource(self):
        return self.resource.subresource.lower()

