# !/usr/bin/env python
# -*- coding:utf-8 -*-


import logging

from oslo.config import cfg

from pyospf import config
from pyospf import version
from pyospf import log
from core.ospfProbe import init


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def main(args=None):
    try:
        CONF(args=args, project='pyospf', version=version,
             default_config_files=['../etc/pyospf.ini'])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, project='pyospf', version=version)

    log.init_log()
    LOG.info('Log (Re)opened.')
    LOG.info("Configuration:")
    CONF.log_opt_values(LOG, logging.INFO)

    ocfg = dict()
    ocfg['router_id'] = CONF.probe.router_id
    ocfg['area'] = CONF.probe.area
    ocfg['interface'] = CONF.probe.interface_name
    ocfg['ip'] = CONF.probe.ip
    ocfg['mask'] = CONF.probe.mask
    ocfg['hello_interval'] = CONF.probe.hello_interval
    ocfg['link_type'] = CONF.probe.link_type
    ocfg['options'] = CONF.probe.options
    ocfg['mtu'] = CONF.probe.mtu
    ocfg['rxmt_interval'] = CONF.probe.rxmt_interval

    init(ocfg)

