# -*- coding: utf-8 -*-
""" app.routes.auth
~~~~~~~~~~~~~~~~~~~
Provides Auth routes.

"""
from collections.abc import Callable
from datetime import datetime as dt, timedelta
from pathlib import Path
from urllib.parse import unquote

import pygogo as gogo

from attr import dataclass, field, validators
from flask import (
    current_app as app,
    has_app_context,
    redirect,
    request,
    session,
    url_for,
)
from meza.fntools import listize, remove_keys
from riko.dotdict import DotDict

from app import LOG_LEVELS, cache
from app.authclient import (
    FLOW_TYPES,
    AuthClientTypes,
    callback,
    get_auth_client,
    get_json,
)
from app.helpers import flask_formatter as formatter, get_verbosity
from app.providers import Authentication
from app.route_helpers import get_status_resource, _format
from app.routes import PatchedMethodView
from app.utils import extract_field, extract_fields, jsonify, parse_item

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


def process_result(result, fields=None, black_list=None, prefix=None, **kwargs):
    if black_list:
        result = (remove_keys(item, *black_list) for item in result)

    if fields:
        result = (dict(extract_fields(item, *fields)) for item in result)

    result = (dict(parse_item(item, prefix=prefix)) for item in result)

    if kwargs:
        result = ({**item, **kwargs} for item in result)

    return result


@dataclass
class BaseView(PatchedMethodView):
    auth: Authentication = field(default=None, kw_only=True, repr=False)
    resource: Resource = field(default=None, kw_only=True, repr=False)
    provider: Provider = field(default=None, kw_only=True, repr=False)
    methods: list[str] = field(factory=list, kw_only=True, repr=False)
    client: AuthClientTypes = field(init=False, repr=False)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        self.methods = self.methods or ["GET"]

        if self.auth.debug is None:
            self.auth.debug = app.config["DEBUG"]

        verbosity = app.config["VERBOSITY"]
        self.verbosity = get_verbosity(verbosity=verbosity, debug=self.auth.debug)
        logger.setLevel(LOG_LEVELS.get(self.verbosity))

        if not self.auth.auth_id:
            self.auth.auth_id = self.auth.auth_type
        elif not self.auth.auth_type:
            self.auth.auth_type = self.auth.auth_id

        if not self.auth.refresh_url:
            self.auth.refresh_url = self.auth.token_url

        if not self.auth.redirect_uri:
            self.auth.redirect_uri = f"/{self.prefix}-callback"

        if self.auth.username and not self.auth.password:
            self.auth.password = ""

        if not self.auth.flow_type:
            self.auth.flow_type = "web"

        if not self.auth.extractions:
            self.auth.extractions = {}

        if not self.auth.params:
            self.auth.params = {}

        api_url = app.config["API_URL"]

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

        if has_app_context():
            args = (self.prefix, self.auth)
            self.client = get_auth_client(*args, **app.config)
            self.client.attrs = self.client.attrs or {}

    def __repr__(self):
        no_rid = self.resource.resource_path.replace(f"/{self.resource.rid}", "")
        no_srid = no_rid.replace(f"/{self.resource.srid}", "")
        return no_srid.lower().replace("/", "-")

    @property
    def resource_id_prop(self):
        return "srid" if len(self.resource.resource_path.split("/")) >= 2 else "rid"

    @property
    def id(self):
        _id = getattr(self.resource, self.resource_id_prop)
        return str(_id) if _id is not None else ""

    @id.setter
    def id(self, value):
        return setattr(self.resource, self.resource_id_prop, value)

    @property
    def trunc_id(self, value):
        return self.id.split("-")[0]

    @property
    def _params(self):
        params = {}

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

    @property
    def api_url(self):
        url = f"{self.auth.api_base_url}/{self.resource.resource_path}"

        if self.id:
            url += f"/{self.id}"

        if self.auth.api_ext:
            url += f".{self.auth.api_ext}"

        return url

    def get_headers(self, method: str = "GET", headers=None, **kwargs):
        headers = headers or {}

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

        _headers = {**HEADERS, **auth_headers, **resource_headers, **headers}

        for k, v in _headers.items():
            attrs = {k.replace(f"{self.prefix}_", ""): v for k, v in session.items() if k.startswith(self.prefix)}
            attrs.update(self.client.attrs)

            if v and v != (formatted := _format(v, **attrs)):
                _headers[k] = formatted

        return _headers

    def get_json(self, url, **kwargs):
        headers = self.get_headers()
        return get_json(url, self.client, headers=headers, params=self.params, **kwargs)


class Callback(BaseView):
    def get(self):
        return callback(self.prefix, self.auth)


class Auth(BaseView):
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

        if self.client.verified and not self.client.expired:
            if self.provider.status_resource:
                status = self.get_json(self.api_url)
                json.update(**status)

            for k in ["state", "realm_id", "token"]:
                try:
                    value = getattr(self.client, k)
                except AttributeError:
                    value = None

                json.update({k: value})

            for key, _path in self.auth.extractions.items():
                path = f"result{_path}" if _path.startswith("[") else f"result.{_path}"
                value = extract_field(json, path)

                if value:
                    self.client.attrs = self.client.attrs or {}
                    session_key = f"{self.prefix}_{key}"
                    self.client.attrs[key] = session[session_key] = json[key] = value
                    logger.debug(f"Set {self.client} attrs[{key}] to {value}.")
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


@dataclass
class APIResource(BaseView):
    """An API Resource.

    Args:
        prefix (str): The API.
        resource (str): The API resource.

    Kwargs:
        rid (str): The API resource_id.
        subkey (str): The API result field to return.

    Examples:
        >>> kwargs = {"subkey": "manufacturer"}
        >>> opencart_manufacturer = Resource("OPENCART", "products", **kwargs)
        >>>
        >>> kwargs = {"subkey": "person"}
        >>> cloze_person = Resource("CLOZE", "people", **kwargs)
        >>>
        >>> params = {
        ...     "start_date: start,
        ...     "end_date": end,
        ...     "columns": "name,net_amount"
        ... }
        >>> kwargs = {"params": params}
        >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
    """

    black_list: set[str] = field(converter=set, factory=set, kw_only=True, repr=False)

    filterer: Callable = field(
        default=None,
        validator=validators.optional(validators.is_callable()),
        kw_only=True,
        repr=False,
    )

    processor: Callable = field(
        default=process_result,
        validator=validators.is_callable(),
        kw_only=True,
        repr=False,
    )

    error_msg: str = field(default="", init=False, repr=False)
    _data: list[dict] = field(factory=list, init=False)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()

        if "dry_run" in self.kwargs:
            self.dry_run = self.kwargs["dry_run"]

        if "datefmt" in self.kwargs:
            self.resource.datefmt = self.kwargs["datefmt"]

        if "end" in self.kwargs:
            self.resource.end = self.kwargs["end"]

        if "use_default" in self.kwargs:
            self.resource.use_default = self.kwargs["use_default"]

        if "dictify" in self.kwargs:
            self.resource.dictify = self.kwargs["dictify"]

        if "pos" in self.kwargs:
            self.resource.pos = int(self.kwargs["pos"])

        fields = self.resource.fields

        if not self.resource.id_field:
            try:
                self.resource.id_field = next(
                    f for f in fields if f.lower().endswith("_id") or f.endswith("Id")
                )
            except StopIteration:
                self.resource.id_field = "id"

        if not self.resource.name_field:
            try:
                self.resource.name_field = next(
                    f for f in fields if f.lower().endswith("name")
                )
            except StopIteration:
                self.resource.name_field = "name"

        if not self.resource.start:
            self.resource.start = self.resource.end - timedelta(days=self.resource.days)

    def __getitem__(self, key):
        return self.data[key]

    def __iter__(self):
        yield from self.data.values() if self.resource.dictify else self.data

    def __repr__(self):
        name = self.resource.resource_path

        if self.id:
            name += f" [id:{self.trunc_id}]"
        else:
            name += (
                f" [pos:{self.resource.pos}]"
                if self.resource.use_default
                else " [all ids]"
            )

        return name

    @property
    def data(self):
        if self._data is None:
            data = self.get()

            if self.resource.dictify:
                id_field = self.resource.id_field
                self._data = dict((item.get(id_field), item) for item in data)
            else:
                self._data = data

        return self._data

    def _extract_model(self, result=None, _id=None, strict=False, **kwargs):
        result = result or []
        error = ""

        if self.id:
            id_field = self.resource.id_field

            try:
                model = next(m for m in result if m.get(id_field) == self.id)
            except StopIteration:
                error = f"{self} with id {id_field} not found!"
                model = {}
        else:
            try:
                model = result[self.resource.pos]
            except (IndexError, TypeError):
                error = f"{self} at pos {self.resource.pos} not found!"
                model = {}

        if model:
            self.id = model.get(self.resource.id_field)

            if strict:
                assert self.id, f"{self} has no ID!"
        elif strict:
            assert model, error

        return model

    def _extract_collection(self, result=None, _id=None, strict=False, **kwargs):
        result = result or []

        if strict:
            assert result, f"{self} has no collection!"

        return result

    def extract_model(self, _id=None, strict=False, **kwargs):
        json = self.get_json(_id, **kwargs)
        return self._extract_model(_id=_id, strict=strict, **json)

    def extract_collection(self, strict=False, **kwargs):
        json = self.get_json(**kwargs)
        return self._extract_collection(strict=strict, **json)

    def extract(self, *args, **kwargs):
        json = self.get_json(**kwargs)

        if self.id or self.resource.use_default:
            result = self._extract_model(*args, **kwargs, **json)
        else:
            result = self._collection(*args, **kwargs, **json)

        return result

    def filter_result(self, *args):
        if self.filterer and not self.id:
            result = list(filter(self.filterer, args))
        else:
            result = args

        return result

    def get_json(self, _id=None, **kwargs):
        """Get an API Resource.
        Kwargs:
            rid (str): The API resource_id.

        Examples:
            >>> kwargs = {"rid": "abc", "subkey": "manufacturer"}
            >>> opencart_manufacturer = Resource("OPENCART", "products", **kwargs)
            >>> opencart_manufacturer.get()
            >>>
            >>> kwargs = {"subkey": "person"}
            >>> cloze_person = Resource("CLOZE", "people", **kwargs)
            >>> cloze_person.get(rid="name@company.com")
            >>>
            >>> kwargs = {"fields": ["name", "net_amount"], "start": start}
            >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
            >>> qb_transactions.get()
        """
        kwargs["headers"] = self.get_headers(**kwargs)
        kwargs["params"] = {**self.params, **kwargs.get("params", {})}

        if _id:
            self.id = _id

        _id = self.id
        json = get_json(self.api_url, self.client, **kwargs)

        if json["ok"]:
            try:
                result = DotDict(json).get(self.resource.result_key) or []
            except KeyError:
                result = []

            args = (listize(result), self.resource.fields)
            _result = list(self.processor(*args, prefix=self.prefix))
            result = self.filter_result(*_result)
        else:
            result = []

        if self.error_msg:
            logger.error(self.error_msg)
            json["message"] = f"{self.error_msg}: {self.api_url}"

        json["result"] = result
        return json

    def get(self, **kwargs):
        """Get an API Resource.
        Kwargs:
            rid (str): The API resource_id.

        Examples:
            >>> kwargs = {"rid": "abc", "subkey": "manufacturer"}
            >>> opencart_manufacturer = Resource("OPENCART", "products", **kwargs)
            >>> opencart_manufacturer.get()
            >>>
            >>> kwargs = {"subkey": "person"}
            >>> cloze_person = Resource("CLOZE", "people", **kwargs)
            >>> cloze_person.get(rid="name@company.com")
            >>>
            >>> kwargs = {"fields": ["name", "net_amount"], "start": start}
            >>> qb_transactions = Resource("qb", "TransactionList", **kwargs)
            >>> qb_transactions.get()
        """
        json = self.get_json(**kwargs)

        if self.resource.use_default and not self.id:
            json["result"] = self._extract_model(**json)

        return jsonify(**json)
