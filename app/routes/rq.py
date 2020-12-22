# -*- coding: utf-8 -*-
""" app.routes.rq
~~~~~~~~~~~~~~~~~
Provides RQ routes.

"""

import pygogo as gogo

from flask import Blueprint, current_app as app, url_for

from flask.views import MethodView
from rq import Queue

from config import Config
from app.utils import jsonify, parse_kwargs
from app.connection import conn

if conn:
    queue = Queue(connection=conn)
else:
    queue = None

# https://requests-oauthlib.readthedocs.io/en/latest/index.html
blueprint = Blueprint("API", __name__)

logger = gogo.Gogo(__name__, monolog=True).logger
logger.propagate = False

# these don't change based on mode, so no need to do app.config['...']
PREFIX = Config.API_URL_PREFIX
FAILURE_TTL = Config.FAILURE_TTL

JOB_STATUSES = {
    "deferred": 202,
    "queued": 202,
    "started": 202,
    "finished": 200,
    "failed": 500,
    "job not found": 404,
}


def get_json_response(job):
    with app.test_request_context():
        if job:
            job_status = job.get_status()
            job_result = job.result
            jid = job.id
        else:
            job_status = "job not found"
            job_result = {}
            jid = 0

        result = {
            "status_code": JOB_STATUSES[job_status],
            "jid": jid,
            "job_status": job_status,
            "job_result": job_result,
            "url": url_for(".result", jid=jid, _external=True),
        }

        return {"ok": job_status != "failed", "result": result}


def get_json_response_by_id(jid):
    """ Displays a job result.

    Args:
        jid (str): The job id.
    """
    job = queue.fetch_job(jid)
    return get_json_response(job)


def _expensive(*args, **kwargs):
    pass


def expensive(*args, enqueue=False, **kwargs):
    failure_ttl = kwargs.pop("failure_ttl", FAILURE_TTL)

    if enqueue:
        job = queue.enqueue(_expensive, *args, **kwargs, failure_ttl=failure_ttl)
        json = get_json_response(job)
    else:
        json = _expensive(*args, **kwargs)

    return json


class Expensive(MethodView):
    def __init__(self):
        self.kwargs = parse_kwargs(app)

    def post(self):
        """ Create work
        """
        json = expensive("arg", **self.kwargs)
        return jsonify(**json)

    def get(self):
        """ Retrieve work
        """
        json = expensive("arg", **self.kwargs)
        return jsonify(**json)
