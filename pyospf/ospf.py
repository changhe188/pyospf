# !/usr/bin/env python
# -*- coding:utf-8 -*-


import logging

from oslo.config import cfg

from pyospf import config
from pyospf import version
from pyospf import log
from core.core import init_probe


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

    probe_cfg = dict()
    probe_cfg['router_id'] = CONF.probe.router_id
    probe_cfg['area'] = CONF.probe.area
    probe_cfg['interface'] = CONF.probe.interface_name
    probe_cfg['ip'] = CONF.probe.ip
    probe_cfg['mask'] = CONF.probe.mask
    probe_cfg['hello_interval'] = CONF.probe.hello_interval
    probe_cfg['link_type'] = CONF.probe.link_type
    probe_cfg['options'] = CONF.probe.options
    probe_cfg['mtu'] = CONF.probe.mtu
    probe_cfg['rxmt_interval'] = CONF.probe.rxmt_interval
    probe_cfg['packet_display'] = CONF.probe.packet_display

    api_cfg = dict()
    api_cfg['bind_host'] = CONF.api.bind_host
    api_cfg['bind_port'] = CONF.api.bind_port
    api_cfg['username'] = CONF.api.username
    api_cfg['password'] = CONF.api.password

    all_cfg = dict()
    all_cfg['PROBE'] = probe_cfg
    all_cfg['API'] = api_cfg

    init_probe(all_cfg)