# -*- coding: utf-8 -*-
"""
    app.route_helpers
    ~~~~~~~~~~~~~~~~~

    Provides route helper functions
"""
from collections import Counter
from dataclasses import asdict
from os import getenv

import pygogo as gogo


from app.helpers import flask_formatter as formatter, toposort
from app.providers import Authentication, Provider

logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


def _format(value, **kwargs):
    try:
        return value.format(**kwargs)
    except AttributeError:
        return value


def getattrs(obj, *attrs):
    attr = getattr(obj, attrs[0])

    if len(attrs) > 1:
        attr = getattrs(attr, *attrs[1:])

    return attr


def get_authentication(*args: Authentication, auth_type: str = None) -> Authentication:
    authentication = None

    if auth_type:
        for authentication in args:
            if authentication.auth_type == auth_type:
                break
        else:
            raise AssertionError(f"authType `{auth_type}` is missing from auth!")
    else:
        if len(args) > 1:
            for _, authentication in toposort(*args, id_key="auth_type"):
                if authentication.is_default:
                    break
            else:
                raise AssertionError("No default auth found in provider!")
        elif args:
            authentication = args[0]
        else:
            raise AssertionError("No auths found in provider!")

    return authentication


def snake_to_pascal_case(text: str) -> str:
    return "".join(word.title() for word in text.split("_"))


def augment_auth(provider: Provider, authentication: Authentication):
    authentication.attrs = authentication.attrs or {}

    if authentication.parent:
        parent = get_authentication(*provider.auths, auth_type=authentication.parent)

        for k, v in asdict(parent).items():
            if v and not getattr(authentication, k):
                setattr(authentication, k, v)

        parent_attrs = parent.attrs or {}
        [authentication.attrs.setdefault(k, v) for k, v in parent_attrs.items()]

    for k, v in asdict(authentication).items():
        try:
            is_env = v.startswith("$")
        except AttributeError:
            is_env = False

        if is_env:
            env = v.lstrip("$")
            setattr(authentication, k, getenv(env))


def validate_providers(*args: Provider):
    prefix_counts = Counter(provider.prefix for provider in args)
    most_common = prefix_counts.most_common(1)

    if most_common[0][1] > 1:
        for prefix, count in most_common:
            raise AssertionError(
                f"The provider prefix `{prefix}` is specified {count} times!"
            )
