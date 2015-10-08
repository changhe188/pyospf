#!/usr/bin/env python
# -*- coding:utf-8 -*-

import logging

from ospfInstance import OspfInstance


LOG = logging.getLogger(__name__)


def init(config):
    oi = OspfInstance(config)
    oi.run()


def init_service():
    pass





