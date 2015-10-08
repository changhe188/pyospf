#!/usr/bin/env python
# -*- coding:utf-8 -*-

import logging
import threading

from ospfInstance import OspfInstance
from pyospf.api.api import init_api

LOG = logging.getLogger(__name__)


def init_probe(config):
    LOG.info('[Probe] Init probe.')
    oi = OspfInstance(config['PROBE'])

    LOG.info('[API] Init API server.')
    api_thrd = threading.Thread(target=init_api, args=(config['API'], oi))
    api_thrd.setDaemon(True)
    api_thrd.start()

    oi.run()


def init_service():
    pass





