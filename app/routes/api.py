# -*- coding: utf-8 -*-
"""
    app.routes.api
    ~~~~~~~~~~~~~~

    Provides additional api endpoints
"""
from collections.abc import Sequence
from importlib import import_module

import pygogo as gogo

from flask import Blueprint, current_app as app

from app.helpers import flask_formatter as formatter, get_member, toposort
from app.route_helpers import augment_resource, get_status_resource
from app.routes.auth import APIResource
from app.utils import (
    cache_header,
    camel_to_snake_case,
    get_links,
    jsonify,
    make_cache_key,
)
from config import Config

try:
    from app.api_configs import BlueprintRouteParams, MethodViewRouteParams
except ImportError:
    BlueprintRouteParams = MethodViewRouteParams = None

try:
    from app.providers import Provider, Resource
except ImportError:
    Provider = Resource = None

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False
blueprint = Blueprint("API", __name__)

ROUTE_TIMEOUT = Config.ROUTE_TIMEOUT
PREFIX = Config.API_URL_PREFIX


def create_route(view, name, *args, methods=None, **kwargs):
    methods = methods or ["GET"]
    view_func = view.as_view(name, *args, **kwargs)
    url = f"{PREFIX}/{name}"

    for param in kwargs.get("params", []):
        url += f"/<{param}>"

    print(f"new route {url}!")
    blueprint.add_url_rule(url, view_func=view_func, methods=methods)


def create_resource_route(
    resource: Resource,
    provider: Provider,
    resource_id: str = None,
    **kwargs,
):
    prefix = provider.prefix
    resource_id = resource_id or resource.resource_id
    converted = camel_to_snake_case(resource_id).replace("_", "-")
    name = f"{prefix}-{converted}"
    create_route(
        APIResource,
        name,
        prefix,
        methods=resource.methods,
        resource=resource,
        provider=provider,
        **kwargs,
    )


def create_resource_routes(provider: Provider, **kwargs):
    if provider.resources:
        for _, resource in toposort(*provider.resources, id_key="resource_id"):
            augment_resource(provider, resource)

            if not resource.hidden:
                create_resource_route(resource, provider, **kwargs)

            if resource.resource_id == provider.status_resource:
                create_resource_route(
                    resource, provider, resource_id="status", **kwargs
                )


def create_method_view_route(
    params: MethodViewRouteParams,
    provider: Provider = None,
    prefix: str = None,
    **kwargs,
):
    module = import_module(params.module)
    view = get_member(module, params.class_name)
    name = f"{prefix}-{params.name}" if prefix else params.name
    resource = get_status_resource(provider) if "-auth" in name else None

    create_route(
        view,
        name,
        prefix,
        methods=params.methods,
        resource=resource,
        provider=provider,
        **kwargs,
    )


def create_blueprint_route(params: BlueprintRouteParams, **kwargs):
    module = import_module(params.module)
    view_func = get_member(module, params.func_name, classes_only=False)
    blueprint.route(f"{PREFIX}/{params.name}")(view_func)
    print(f"new route {PREFIX}/{params.name}!")


def create_home_route(description: str, message: str):
    def home():
        json = {
            "description": description,
            "message": message,
            "links": get_links(app.url_map.iter_rules()),
        }

        return jsonify(**json)

    view_func = cache_header(ROUTE_TIMEOUT, key_prefix=make_cache_key)(home)
    blueprint.route("/")(view_func)
    blueprint.route(PREFIX)(view_func)
    print("new home route!")
