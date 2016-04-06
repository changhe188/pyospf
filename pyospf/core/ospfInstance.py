#!/usr/bin/env python
# -*- coding:utf-8 -*-


import signal
import time
import logging

from ospfArea import OspfArea
from ospfReceiver import OspfReceiver
from ospfLsdb import OspfLsdb
from ospfStat import OspfStat
from pyospf.basic.ospfSock import OspfSock
from pyospf.basic.constant import ISM_STATE
from pyospf.protocols.protocol import OspfProtocol
from pyospf.utils import util

LOG = logging.getLogger(__name__)


class OspfInstance(object):
    """
    OSPF instance skeleton class
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(OspfInstance, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, config):

        self.start_time = util.current_time()
        self.area_list = dict()
        self.backbone = None        # unused
        self.virtual_link = None     # unused
        self.external_router = list()    # unused

        self.as_external_lsa = dict()     # type-5 lsa list
        self.nssa_lsa = dict()           # type-7 lsa list
        self.opaque11_lsa = dict()       # type-11 lsa list

        self.config = config

        self.rid = self.config['router_id']
        self.interface_mame = self.config['interface']
        self.local_ip = self.config['ip']

        # Check config parameters legality
        if self.config['hello_interval'] < 1 or self.config['hello_interval'] > 65535:
            LOG.critical('[OSPF Instance] Hello interval is beyond the limitation.')
            return
        try:
            self.config['options'] = OspfProtocol.parse_options_config(self.config['options'])
        except Exception:
            LOG.critical('[OSPF Instance] Options is illegal.')
            return

        # The probe only connect to one area, so area list has no meaning.
        self.area = OspfArea(self)
        self.area_list[self.area.area_id] = self.area

        self.lsdb = OspfLsdb(self)

        self.recv = OspfReceiver(self.area.interface, self.area.interface.nbr_list, self.config['packet_display'])
        self._sock = None   # socket for receiving ospf packets

        # Statistics
        self.stat = OspfStat()

    def run(self):
        """
        Main thread
        """
        # gives an interface up message to ism
        self.area.interface.fire('ISM_InterfaceUp')
        if self.area.interface.state == ISM_STATE['ISM_Down']:
            LOG.error('[OSPF Instance] Interface up failed.')
            return

        # open a socket to listen ospf port to avoid sending icmp protocol unreachable
        self._sock = OspfSock()
        self._sock.bind_ospf_multicast_group(self.interface_mame)
        self._sock.add_ospf_multicast_group(self.local_ip)

        # bind signal handler to handle terminal signal
        signal.signal(signal.SIGTERM, self.term_handler)
        signal.signal(signal.SIGINT, self.term_handler)

        while True:
            (data, src) = self._sock.recv()
            (src_ip, port) = src
            if src_ip == self.local_ip:       # filter to drop all packets from self
                continue

            self.recv.ospf_handler(data, time.time())

    def term_handler(self, a, b):
        LOG.debug('[OSPF Instance] Signal %s is received.' % str(a))
        self.exit()

    def exit(self):
        self._sock.drop_ospf_multicast_group(self.local_ip)
        self._sock.close()
        LOG.info('[OSPF Instance] Program exits.')
        exit(0)
