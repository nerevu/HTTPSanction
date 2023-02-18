# -*- coding: utf-8 -*-
"""
    app.routes.api
    ~~~~~~~~~~~~~~

    Provides additional api endpoints
"""
from importlib import import_module

from flask import Blueprint, current_app as app

from app.helpers import get_member
from app.utils import cache_header, get_links, jsonify, make_cache_key
from config import Config

try:
    from app.api_configs import BlueprintRouteParams, MethodViewRouteParams
except ImportError:
    BlueprintRouteParams = MethodViewRouteParams = None

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


def create_method_view_route(params: MethodViewRouteParams, prefix=None, **kwargs):
    module = import_module(params.module)
    view = get_member(module, params.class_name)
    name = f"{prefix}-{params.name}" if prefix else params.name
    create_route(view, name, prefix, methods=params.methods, **kwargs)


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
