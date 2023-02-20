# -*- coding: utf-8 -*-
"""
    app.route_helpers
    ~~~~~~~~~~~~~~~~~

    Provides route helper functions
"""
from collections import Counter
from dataclasses import asdict
from os import getenv, path as p

import pygogo as gogo
from dotenv import load_dotenv

from app.helpers import flask_formatter as formatter, toposort
from app.providers import Authentication, Provider

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


PARENT_DIR = p.abspath(p.dirname(p.dirname(__file__)))

load_dotenv(p.join(PARENT_DIR, ".env"), override=True)


def getattrs(obj, *attrs):
    attr = getattr(obj, attrs[0])

    if len(attrs) > 1:
        attr = getattrs(attr, *attrs[1:])

    return attr


def get_authentication(*args: Authentication, auth_id: str = None) -> Authentication:
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
            raise AssertionError("No auths found in provider!")

    return authentication


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
            if is_listlike(formatted):
                formatted = [_format(v) for v in value]

    return formatted


def augment_auth(provider: Provider, authentication: Authentication):
    authentication.attrs = authentication.attrs or {}
    kwargs = {}

    if authentication.parent:
        parent = get_authentication(*provider.auths, auth_id=authentication.parent)
        parentAsdict = asdict(parent)
        kwargs.update(parentAsdict)

        for k, v in parentAsdict.items():
            if v and not getattr(authentication, k):
                setattr(authentication, k, v)

        parent_attrs = parent.attrs or {}
        [authentication.attrs.setdefault(k, v) for k, v in parent_attrs.items()]

    authAsdict = asdict(authentication)
    kwargs.update(authAsdict)
    kwargs.update(authentication.attrs)

    for k, v in authAsdict.items():
        if v:
            replaced = replace_envs(v)
            setattr(authentication, k, replaced)

    authAsdict = asdict(authentication)
    kwargs.update(authAsdict)
    kwargs.update(authentication.attrs)

    for k, v in authAsdict.items():
        if v:
            formatted = _format(v, **kwargs)
            setattr(authentication, k, formatted)


def validate_providers(*args: Provider):
    prefix_counts = Counter(provider.prefix for provider in args)
    most_common = prefix_counts.most_common(1)

    if most_common[0][1] > 1:
        for prefix, count in most_common:
            raise AssertionError(
                f"The provider prefix `{prefix}` is specified {count} times!"
            )
