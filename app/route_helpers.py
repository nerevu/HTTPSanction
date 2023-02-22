# -*- coding: utf-8 -*-
"""
    app.route_helpers
    ~~~~~~~~~~~~~~~~~

    Provides route helper functions
"""
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict
from os import getenv, path as p

import pygogo as gogo

from dotenv import load_dotenv

from app.helpers import flask_formatter as formatter, toposort

try:
    from app.providers import (
        AttrClass,
        Authentication,
        AuthenticationHeaders,
        HeadlessElement,
        MethodMap,
        ParamMap,
        Provider,
        Resource,
        ResourceHeaders,
    )
except ImportError:
    Authentication = (
        Provider
    ) = (
        Resource
    ) = (
        AuthenticationHeaders
    ) = MethodMap = ParamMap = HeadlessElement = AttrClass = ResourceHeaders = None

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


PARENT_DIR = p.abspath(p.dirname(p.dirname(__file__)))

load_dotenv(p.join(PARENT_DIR, ".env"), override=True)


def get_attrs(obj, *attrs):
    attr = getattr(obj, attrs[0])

    if len(attrs) > 1:
        attr = get_attrs(attr, *attrs[1:])

    return attr


def get_authentication(
    *args: Sequence[Authentication], auth_id: str = None
) -> Authentication:
    authentication = None

    if auth_id:
        for authentication in args:
            if authentication.auth_id == auth_id:
                break
        else:
            raise AssertionError(f"authId `{auth_id}` is missing from auth!")
    else:
        if len(args) > 1:
            for _, authentication in toposort(*args, id_key="auth_id"):
                if authentication.is_default:
                    break
            else:
                raise AssertionError("No default auth found in provider!")
        elif args:
            authentication = args[0]
        else:
            raise AssertionError("No auths found in provider !")

    return authentication


def get_resource(*args: Sequence[Resource], resource_id: str = None) -> Resource:
    resource = None

    for resource in args:
        if resource.resource_id == resource_id:
            break

    return resource


def get_status_resource(provider):
    resource = None

    if provider and provider.resources:
        resource = get_resource(
            *provider.resources, resource_id=provider.status_resource_id
        )

    return resource


def is_listlike(item):
    attrs = {"append", "next", "__reversed__", "__next__"}
    return attrs.intersection(dir(item))


def replace_envs(value):
    replaced = value
    is_env = False

    try:
        is_env = value.startswith("$")
    except AttributeError:
        try:
            replaced = {k: replace_envs(v) for k, v in value.items()}
        except AttributeError:
            if is_listlike(replaced):
                replaced = [replace_envs(v) for v in value]

    if is_env:
        env = value.lstrip("$")
        replaced = getenv(env)

        if not replaced:
            logger.error(f"Env `{env}` not found in environment!")

    return replaced


def _format(value, **kwargs):
    formatted = value

    try:
        formatted = value.format(**kwargs)
    except AttributeError:
        try:
            formatted = {k: _format(v, **kwargs) for k, v in value.items()}
        except AttributeError:
            if is_listlike(value):
                formatted = [_format(v) for v in value]

    return formatted


def gen_attrs(value):
    for k, _v in value.items():
        v = AttrClass.from_dict(_v) if hasattr(_v, "items") else _v
        yield k, v


def set_auth_attr(authentication: Authentication, key: str, value):
    converters = {
        "headers": AuthenticationHeaders.from_dict,
        "method_map": MethodMap.from_dict,
        "param_map": ParamMap.from_dict,
    }

    if from_dict := converters.get(key):
        value = from_dict(value)
    elif key == "headless_elements":
        value = [HeadlessElement.from_dict(element) for element in value]
    elif key in {"attrs", "params"}:
        value = dict(gen_attrs(value))

    setattr(authentication, key, value)


def set_resource_attr(resource: Resource, key: str, value):
    if key == "headers":
        value = ResourceHeaders.from_dict(value)
    elif key in {"attrs", "params"}:
        value = dict(gen_attrs(value))

    setattr(resource, key, value)


def augment_auth(provider: Provider, authentication: Authentication):
    authentication.attrs = authentication.attrs or {}
    kwargs = {}

    if authentication.parent:
        parent = get_authentication(*provider.auths, auth_id=authentication.parent)
        parentAsdict = asdict(parent)
        kwargs.update(parentAsdict)

        for k, v in parentAsdict.items():
            if v and not getattr(authentication, k):
                set_auth_attr(authentication, k, v)

        parent_attrs = parent.attrs or {}
        [authentication.attrs.setdefault(k, v) for k, v in parent_attrs.items()]

    authAsdict = asdict(authentication)
    kwargs.update(authAsdict)
    kwargs.update(authentication.attrs)

    for k, v in authAsdict.items():
        if v and v != (replaced := replace_envs(v)):
            set_auth_attr(authentication, k, replaced)

    authAsdict = asdict(authentication)
    kwargs.update(authAsdict)
    kwargs.update(authentication.attrs)

    for k, v in authAsdict.items():
        if v and v != (formatted := _format(v, **kwargs)):
            set_auth_attr(authentication, k, formatted)


def augment_resource(provider: Provider, resource: Resource):
    _resource = f"{provider.prefix}/{resource.resource_id}"

    if resource.parent:
        parent = get_resource(*provider.resources, resource_id=resource.parent)

        if parent:
            resource.auth_id = resource.auth_id or parent.auth_id
            resource.resource_name = resource.resource_name or parent.resource_name
            # resource.parent = parent
        else:
            raise AssertionError(
                f"No parent resource with resourceId {resource.parent} found."
            )

    resource.resource_name = resource.resource_name or resource.resource_id
    authentication = get_authentication(*provider.auths, auth_id=resource.auth_id)
    kwargs = authentication.attrs or {}
    kwargs.update(resource.attrs or {})

    for k, v in asdict(resource).items():
        if v and v != (formatted := _format(v, **kwargs)):
            set_resource_attr(resource, k, formatted)

    assert resource.auth_id, f"{_resource} is missing auth_id!"
    assert resource.resource_name, f"{_resource} is missing resource_name!"


def validate_providers(*args: Provider):
    prefix_counts = Counter(provider.prefix for provider in args)
    most_common = prefix_counts.most_common(1)

    if most_common[0][1] > 1:
        for prefix, count in most_common:
            raise AssertionError(
                f"The provider prefix `{prefix}` is specified {count} times!"
            )

    for provider in args:
        id_counts = Counter(resource.resource_id for resource in provider.resources)
        most_common = id_counts.most_common(1)

        if most_common[0][1] > 1:
            for resource_id, count in most_common:
                _path = f"{provider.prefix}/resources[?]/{resource_id}"
                raise AssertionError(
                    f"The resourceId {_path} is specified {count} times!"
                )

        id_counts = Counter(auth.auth_id for auth in provider.auths)
        most_common = id_counts.most_common(1)

        if most_common[0][1] > 1:
            for auth_id, count in most_common:
                _path = f"{provider.prefix}/auths[?]/{auth_id}"
                raise AssertionError(f"The authId {_path} is specified {count} times!")
