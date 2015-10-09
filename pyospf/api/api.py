# !/usr/bin/env python
# -*- coding:utf-8 -*-

import json
import logging
from functools import wraps
from oslo_config import cfg
from flask import Flask, request, Response


from pyospf.utils import util


app = Flask(__name__)
LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def return_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        r = f(*args, **kwargs)
        return Response(r, content_type='application/json; charset=utf-8')
    return decorated_function


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if need_auth:
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
        return f(*args, **kwargs)
    return decorated


def check_auth(usr, pwd):
    """This function is called to check if a username /
    password combination is valid.
    """
    return usr == username and pwd == password


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Auth Required"'})


@app.route('/lsdb')
@app.route('/lsdb/<ltype>')
@requires_auth
@return_json
def lsdb(ltype=None):
    lsdb = ospf_instance.lsdb.lsdb
    lsdb_no_tuple = dict()
    if ltype:
        if not ltype in lsdb:
            return json.dumps({})
        else:
            lsdb_no_tuple[ltype] = dict([(str(k), v) for k, v in lsdb[ltype].items()])
    else:
        for lsa_type in lsdb:
            lsdb_no_tuple[lsa_type] = dict([(str(k), v) for k, v in lsdb[lsa_type].items()])
    return json.dumps(lsdb_no_tuple)


@app.route('/lsdb_summary')
@requires_auth
@return_json
def lsdb_summary():
    lsdb = ospf_instance.lsdb.lsdb
    lsdb_summary = dict()
    total_lsa = 0
    for lsa_type in lsdb:
        total_lsa += len(lsdb[lsa_type])
        lsdb_summary[lsa_type] = len(lsdb[lsa_type])
    lsdb_summary['total_lsa'] = total_lsa

    return json.dumps(lsdb_summary)


@app.route('/stats')
@requires_auth
@return_json
def stats():
    stat = ospf_instance.stat.get_stat_all()
    return json.dumps(stat)


@app.route('/probe')
@requires_auth
@return_json
def probe():
    start_time = ospf_instance.start_time
    running_time = util.current_time() - start_time
    router_id = ospf_instance.rid

    probe = {
        'router_id': router_id,
        'start_time': str(start_time),
        'running_time': str(running_time),
        }
    return json.dumps(probe)


def init_api(config, oi):
    global ospf_instance
    ospf_instance = oi

    bind_host = config['bind_host']
    bind_port = config['bind_port']

    global need_auth, username, password
    need_auth = config['auth']
    if need_auth:
        username = config['username']
        password = config['password']

    app.run(host=bind_host, port=bind_port)