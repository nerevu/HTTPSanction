# -*- coding: utf-8 -*-
""" app.api
~~~~~~~~~~~~
Provides endpoints for authenticating with and pulling data from quickbooks.

Live Site:
    https://alegna-api.nerevu.com/v1

Endpoints:
    Visit the live site for a list of all available endpoints
"""
import hmac

from base64 import b64encode

import pygogo as gogo

from attr import dataclass, field
from flask import current_app as app, request
from meza.fntools import listize

from app.helpers import flask_formatter as formatter
from app.routes import PatchedMethodView
from app.utils import extract_field, get_links, jsonify, parse_request

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
# https://oauth-pythonclient.readthedocs.io/en/latest/index.html
logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


@dataclass
class Webhook(PatchedMethodView):
    actions: dict = field(factory=dict, kw_only=True, repr=False)
    activities: dict = field(factory=list, kw_only=True, repr=False)

    def __attrs_post_init__(self, *args, **kwargs):
        super().__attrs_post_init__(*args, **kwargs)
        self.digest = self.digest or "sha256"

    # https://github.com/bloomberg/python-github-webhook
    # https://github.com/carlos-jenkins/python-github-webhooks
    # https://github.com/nickfrostatx/flask-hookserver
    @property
    def verified(self):
        if self.ignore_signature:
            is_valid = True
        elif not self.payload_key:
            is_valid = False
        elif self.signature_header and self.webhook_secret:
            signature = request.headers.get(self.signature_header).encode("utf-8")

            if self.split_signature:
                signature = signature.split("=")[1]

            secret = self.webhook_secret.encode("utf-8")

            if self.b64_encode:
                mac_digest = hmac.digest(secret, request.data, self.digest)
                calculated_hmac = b64encode(mac_digest)
            elif self.digest:
                mac = hmac.new(secret, request.data, self.digest)
                calculated_hmac = mac.hexdigest()
            else:
                calculated_hmac = secret

            is_valid = hmac.compare_digest(calculated_hmac, signature)
        else:
            is_valid = False

        return is_valid

    def get(self, activity_name=None):
        json = {
            "description": f"The {self.prefix} webhook.",
            "payload_key": self.payload_key,
        }
        action = self.actions.get(activity_name) if activity_name else None

        if activity_name and action:
            json["description"] = action.__doc__
            json["activity"] = activity_name
            json["action"] = action.__name__
            json["kwargs"] = {}

            for x in self.activities:
                if x["name"] == activity_name:
                    json["kwargs"].update(x.get("kwargs", {}))
                    break

            json["kwargs"].update(parse_request())

        elif activity_name:
            json["description"] = f"Activity {activity_name} doesn't exist!"
            json["status_code"] = 404
        else:
            json["activities"] = list(self.actions)
        try:
            json["links"] = get_links(app.url_map.iter_rules())
        except RuntimeError:
            pass

        return jsonify(**json)

    def process(self, *args):
        result = {}

        for event in args:
            for key, path in self.extractions.items():
                if value := extract_field(event, path):
                    self.attrs[key] = value

            if self.activity_name:
                activity_name = self.activity_name.format(**self.attrs).lower()

                if action := self.actions.get(activity_name):
                    response = action(**self.attrs).get("response")

                    if self.result_key:
                        if result_key := event.get(self.result_key):
                            result[result_key] = response
                        else:
                            logger.warning(
                                f"Key {self.result_key} doesn't exist in event!"
                            )
                    else:
                        result = response
                else:
                    logger.warning(f"Activity {activity_name} doesn't exist!")

        return result

    def post(self, **kwargs):
        """Respond to a Webhook post."""
        if self.verified:
            payload = parse_request()
            value = payload.get(self.payload_key) if self.payload_key else payload

            if value:
                args = listize(value)
                json = self.process(*args)
            elif self.payload_key:
                message = f"Invalid payload! Ensure key {self.payload_key} is present"
                json = {"message": message, "status_code": 400}
            else:
                message = f"Empty payload!"
                json = {"message": message, "status_code": 400}

        elif self.payload_key:
            json = {"message": "Invalid signature!", "status_code": 401}
        else:
            json = {"message": "Missing payload key!", "status_code": 401}

        json.pop("links", None)
        json.pop("Attachments", None)
        return jsonify(**json)
