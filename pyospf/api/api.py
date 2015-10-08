# !/usr/bin/env python
# -*- coding:utf-8 -*-

import json
import logging

from oslo_config import cfg

from flask import Flask, request


app = Flask(__name__)
LOG = logging.getLogger(__name__)
CONF = cfg.CONF


@app.route('/lsdb')
@app.route('/lsdb/<ltype>')
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

@app.route('/stat')
def stat():
    stat = ospf_instance.stat.get_stat_all()
    return json.dumps(stat)


def init_api(config, oi):
    global ospf_instance
    ospf_instance = oi
    app.run(host='0.0.0.0', port=7000)