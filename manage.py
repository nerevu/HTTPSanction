#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: sw=4:ts=4:expandtab

""" A script to manage development tasks """
import json
import sys

from collections.abc import Iterator
from functools import partial
from glob import glob
from itertools import chain
from os import environ, path as p
from pathlib import Path
from subprocess import CalledProcessError, call, check_call
from sys import exit

import click
import pygogo as gogo
import pyjson5

from click import Choice
from flask import current_app as app
from flask.cli import FlaskGroup, pass_script_info, with_appcontext
from flask.config import Config as FlaskConfig
from jsonschema import Draft7Validator, RefResolver
from jsonschema.exceptions import RefResolutionError, SchemaError
from pathspec import PathSpec
from pyjson5 import Json5EOF

from app import create_app
from app.helpers import configure, email_hdlr, exception_hook
from app.providers import Provider, provider_from_dict
from app.routes.api import (
    create_blueprint_route,
    create_home_route,
    create_method_view_route,
)

from app.route_helpers import (
    augment_auth,
    get_authentication,
    validate_providers,
)

try:
    from app.api_configs import APIConfig, MethodViewRouteParams, api_config_from_dict
except ImportError:
    APIConfig = MethodViewRouteParams = api_config_from_dict = None


ARGS_KEY = f"{__name__}.args"
BASEDIR = p.dirname(__file__)
CLICK_COMMAND_SETTINGS = {"show_default": True}
CONFIG_MODES = ["Test", "Development", "Production", "Ngrok", "Custom", "Heroku"]
DEF_PY_WHERE = "app *.py"
DEF_JSON_WHERE = "app *.json"

DATA_DIRS = {
    "provider": "app/providers",
    "api-config": "app/api_configs",
}
SCHEMAS = list(DATA_DIRS)
SCHEMA_DIR = "app/schemas"


logger = gogo.Gogo(__name__, high_hdlr=email_hdlr).logger
logger.propagate = False

sys.excepthook = partial(exception_hook, debug=True)


def gen_api_configs() -> Iterator[APIConfig]:
    for document in Path(DATA_DIRS["api-config"]).glob("*.json"):
        with document.open() as f:
            yield api_config_from_dict(pyjson5.load(f))


def get_provider(name: str) -> Provider:
    provider_dir = DATA_DIRS["provider"]

    with Path(f"{provider_dir}/{name}.json").open() as f:
        return provider_from_dict(pyjson5.load(f))


def gen_providers(config: APIConfig) -> Iterator[Provider]:
    for name in config.provider_names:
        yield get_provider(name)


class HookGroup(FlaskGroup):
    def invoke(self, ctx):
        ctx.meta[ARGS_KEY] = ctx.args
        return super().invoke(ctx)


def parse_verbosity(verbose=0, quiet=None):
    if quiet:
        verbosity = "0"
    elif verbose:
        verbosity = str(verbose)
    else:
        verbosity = ""

    return verbosity


@click.group(
    cls=HookGroup, create_app=create_app, context_settings=CLICK_COMMAND_SETTINGS
)
@click.option(
    "-m",
    "--config-mode",
    type=Choice(CONFIG_MODES, case_sensitive=False),
    default="Development",
)
@click.option("-f", "--config-file", type=p.abspath)
@click.option("-e", "--config-envvar")
@click.option(
    "-v",
    "--verbose",
    help="Specify multiple times to increase logging verbosity (overridden by -q)",
    count=True,
)
@click.option("-q", "--quiet", help="Only log errors (overrides -v)", is_flag=True)
@click.pass_context
@pass_script_info
def manager(script_info, ctx, verbose=0, quiet=False, **kwargs):
    subcommand = ctx.invoked_subcommand
    cmd = ctx.command.get_command(ctx, subcommand)
    args = ctx.meta.get(ARGS_KEY)
    cmd.parse_args(ctx, args)

    if subcommand == "run":
        script_info.port = ctx.params["port"]
        environ["PORT"] = str(script_info.port)

        for api_config in gen_api_configs():
            [create_method_view_route(params) for params in api_config.method_view_route_params]
            [create_blueprint_route(params) for params in api_config.blueprint_route_params]
            create_home_route(api_config.description, api_config.message)

            for provider in gen_providers(api_config):
                authentication = get_authentication(*provider.auths)
                augment_auth(provider, authentication)
                ckwargs = {"prefix": provider.prefix, "auth": authentication}
                [create_method_view_route(params, **ckwargs) for params in api_config.auth_route_params]
    else:
        verbose = ctx.params["verbose"]

    flask_config = FlaskConfig(BASEDIR)
    configure(flask_config, **kwargs)
    script_info.flask_config = flask_config

    environ["VERBOSITY"] = parse_verbosity(verbose, quiet)

    if flask_config.get("ENV"):
        environ["FLASK_ENV"] = flask_config["ENV"]

    if flask_config.get("DEBUG"):
        environ["FLASK_DEBUG"] = str(flask_config["DEBUG"]).lower()


@manager.command()
@click.pass_context
def serve(ctx):
    """Runs the Flask server"""
    print("Deprecated. Use `manage run` instead.")
    # manager.get_command(ctx, 'run')()


@manager.command()
@click.pass_context
def help(ctx):
    """Shows the help message"""
    commands = "\n          ".join(manager.list_commands(ctx))
    print("Usage: manage <command> [OPTIONS]")
    print(f"commands: {commands}")


def _lint_py(where, strict):
    """Check Python style with flake8"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["flake8"] + paths)

    if strict:
        cmd_args = ["pylint", "--rcfile=tests/standard.rc", "-rn", "-fparseable", "app"]
        check_call(cmd_args)


def _eslint(where, strict):
    """Check json syntax with eslint"""
    where = where or DEF_JSON_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["npx", "eslint"] + paths + ["--ext", ".json"])


def _black(where):
    """Prettify code with black"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["black"] + paths)


def _isort(where):
    """Prettify imports with isort"""
    where = where or DEF_PY_WHERE
    paths = list(chain(*map(glob, where.split(" "))))
    check_call(["isort"] + paths)


def _format_json(where):
    """Prettify json with jq"""
    where = where or "."

    with open(".gitignore") as gitignore:
        lines = gitignore.readlines()
        lines += ["package*.json"]
        spec = PathSpec.from_lines("gitwildmatch", lines)

    for _path in map(Path, where.split(" ")):
        paths = list(_path.glob("**/*.json")) if _path.is_dir() else [_path]
        ignored = spec.match_files(paths)

        for document in set(paths).difference(ignored):
            with document.open() as f:
                try:
                    obj = pyjson5.load(f)
                except Json5EOF:
                    obj = {}

            with document.open("w") as f:
                logger.info(f"Formatting {document.relative_to('.')}")
                formatted = json.dumps(obj, indent=2)
                f.write(formatted)
                f.write("\n")


@manager.command()
def check():
    """Check staged changes for lint errors"""
    exit(call(p.join(BASEDIR, "helpers", "check-stage")))


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
@with_appcontext
def test(where):
    """Run nose tests"""
    exit("Not implemented!")


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
def prettify(where):
    """Prettify code with black"""
    errors = []

    try:
        _black(where)
    except CalledProcessError as e:
        errors += [e]

    try:
        _isort(where)
    except CalledProcessError as e:
        errors += [e]

    try:
        _format_json(where)
    except CalledProcessError as e:
        errors += [e]

    exit(len(errors))


@manager.command()
@click.option("-w", "--where", help="Locations to check (space separated)")
@click.option(
    "-s", "--strict/--no-strict", help="Check Python files with pylint", default=False
)
def lint(where, strict):
    """Check style with linters"""
    errors = []

    try:
        _lint_py(where, strict)
    except CalledProcessError as e:
        errors += [e]

    try:
        _eslint(where, strict)
    except CalledProcessError as e:
        errors += [e]

    exit(len(errors))


@manager.command()
@click.option(
    "-s",
    "--schema",
    type=Choice(SCHEMAS + ["all"]),
    default="provider",
    help="The schemas to use",
)
def schema_to_code(schema):
    """Generate Python code from json schema"""
    num_errors = 0
    schema_names = SCHEMAS if schema == "all" else [schema]
    destinations = ""

    for schema_name in schema_names:
        source = f"{SCHEMA_DIR}/{schema_name}.schema.json"
        _schema = pyjson5.load(open(source))
        dest_dir = DATA_DIRS[schema_name]
        dest = f"{dest_dir}/__init__.py"

        cmd_args = [
            "quicktype",
            "--src-lang=schema",
            source,
            f"--out={dest}",
            "--top-level={title}".format(**_schema),
            "--python-version=3.7",
            "--alphabetize-properties",
        ]

        try:
            check_call(cmd_args)
        except CalledProcessError as e:
            num_errors += 1
            logger.error(e.returncode)
        else:
            destinations += f" {dest}"
            logger.info(f"generated {dest}")

    try:
        _black(destinations)
    except CalledProcessError as e:
        num_errors += 1
        logger.error(e.returncode)

    try:
        _isort(destinations)
    except CalledProcessError as e:
        num_errors += 1
        logger.error(e.returncode)

    exit(num_errors)


@manager.command()
@click.option(
    "-s",
    "--schema",
    type=Choice(SCHEMAS + ["all"]),
    default="all",
    help="The schemas to use",
)
def validate_schema(schema):
    """Validate json schemas"""
    num_errors = 0
    schema_names = SCHEMAS if schema == "all" else [schema]

    for schema_name in schema_names:
        source = f"{SCHEMA_DIR}/{schema_name}.schema.json"
        _schema = pyjson5.load(open(source))

        try:
            Draft7Validator.check_schema(_schema)
        except SchemaError as e:
            num_errors += 1
            logger.error(e)
        else:
            logger.info(f"{source} is valid!")

    exit(num_errors)


@manager.command()
@click.option(
    "-s",
    "--schema",
    type=Choice(SCHEMAS + ["all"]),
    default="all",
    help="The schemas to use",
)
def validate_data(schema):
    """Validate instances against their json schema"""
    num_errors = 0
    schema_names = SCHEMAS if schema == "all" else [schema]
    schemas = (pyjson5.load(open(source)) for source in Path(SCHEMA_DIR).iterdir())
    schema_store = {schema["$id"]: schema for schema in schemas}

    for schema_name in schema_names:
        source = f"{SCHEMA_DIR}/{schema_name}.schema.json"
        dest_dir = DATA_DIRS[schema_name]
        _schema = pyjson5.load(open(source))
        resolver = RefResolver.from_schema(_schema, store=schema_store)

        for document in Path(dest_dir).glob("*.json"):
            with document.open() as f:
                validator = Draft7Validator(_schema, resolver=resolver)
                data = pyjson5.load(f)

                try:
                    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
                except RefResolutionError as e:
                    errors = [e]

                num_errors += len(errors)

                if errors:
                    [logger.error(error) for error in errors]
                else:
                    logger.info(f"{document} is valid!")

        if schema == "provider":
            for api_config in gen_api_configs():
                providers = gen_providers(api_config)

                try:
                    validate_providers(providers)
                except AssertionError as e:
                    num_errors += 1
                    logger.error(e)
                else:
                    logger.info(f"{source} is valid!")

    exit(num_errors)


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def add_keys(remote):
    """Deploy staging app"""
    command = f"heroku keys:add ~/.ssh/id_rsa.pub --remote {remote}"
    exit(call(command.split(" ")))


@manager.command()
@click.option("-r", "--remote", help="the heroku branch", default="staging")
def deploy(remote):
    """Deploy staging app"""
    branch = "master" if remote == "production" else "features"
    command = f"git push origin {branch}"
    exit(call(command.split(" ")))


@manager.command()
def require():
    """Create requirements.txt"""
    command = "pip freeze -l | grep -vxFf dev-requirements.txt "
    command += "| grep -vxFf requirements.txt "
    command += "> base-requirements.txt"
    exit(call(command.split(" ")))


if __name__ == "__main__":
    manager.run()
