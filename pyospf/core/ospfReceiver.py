#!/usr/bin/env python
# -*- coding:utf-8 -*-


import time
import logging

from pyospf.basic.ospfParser import *
from pyospf.basic.constant import *

from pyospf.utils import util
from pyospf.utils.threadpool import ThreadPool


LOG = logging.getLogger(__name__)


class OspfReceiver(object):

    def __init__(self, ism, nsm_list, pkt_display=False):
        self.ism = ism
        self.nsm_list = nsm_list

        self.pkt_dis = 0
        if pkt_display:
            self.pkt_dis = 1

        self.lsu_handler = ThreadPool(1)

    def ospf_handler(self, data, timestamp):
        """
        Distinguish different kind OSPF packet, and call according functions
        """
        if not data:
            return
        LOG.debug('[Receiver] Received packet: %s:%f'
                  % (time.strftime('%H:%M', time.localtime(timestamp)), timestamp % 60))

        pkt = OspfParser.parse(data, verbose=self.pkt_dis)
        if pkt is None:
            LOG.error('[Receiver] Wrong Packet.')
            return False

        self.ism.ai.oi.stat.total_received_packet_count += 1

        hdr = pkt['V']

        ospf_type = hdr['TYPE']
        dst = pkt['H']['DST']
        nrid = hdr['RID']
        aid = hdr['AID']

        LOG.debug('[Receiver] Type: %s, Dst: %s, NRID: %s, Area: %s' %
                  (ospf_type, int2ip(dst), int2ip(nrid), int2ip(aid)))

        if ospf_type == 1:
            LOG.debug('[Receiver] Received a Hello.')
            self.ism.ai.oi.stat.recv_hello_count += 1
            neighborLock.acquire()
            if self.ism.hp.check_hello(pkt):
                self.ism.ai.oi.stat.total_handled_packet_count += 1
                if self.ism.hp.check_active_router(pkt):
                    if self.ism.link_type != 'Point-to-Point':
                        self.ism.hp.get_dr_bdr(pkt)
            neighborLock.release()

        elif ospf_type == 2:
            self.ism.ai.oi.stat.recv_dd_count += 1
            LOG.debug('[Receiver] Received a Database Description from %s to %s.'
                           % (util.int2ip(nrid), util.int2ip(dst)))
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if nrid in self.nsm_list:
                    self.nsm_list[nrid].ep.check_dd(pkt)
                    self.ism.ai.oi.stat.total_handled_packet_count += 1
                else:
                    LOG.debug('[Receiver] DD from %s not handled.' % util.int2ip(nrid))

        elif ospf_type == 3:
            LOG.debug('[Receiver] Received a LSR from %s to %s.' % (util.int2ip(nrid), util.int2ip(dst)))
            self.ism.ai.oi.stat.recv_lsr_count += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if nrid in self.nsm_list:
                    self.nsm_list[nrid].ep.check_lsr(pkt)
                    self.ism.ai.oi.stat.total_handled_packet_count += 1
                else:
                    LOG.debug('[Receiver] LSR from %s not handled.' % util.int2ip(nrid))

        elif ospf_type == 4:
            LOG.debug('[Receiver] Received a LSU from %s to %s.' % (util.int2ip(nrid), util.int2ip(dst)))
            self.ism.ai.oi.stat.recv_lsu_count += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if nrid in self.nsm_list:
                    self.lsu_handler.addTask(self._handle_lsu, (nrid, pkt))
                    self.ism.ai.oi.stat.total_handled_packet_count += 1
                else:
                    LOG.warn('[Receiver] LSU from %s not handled.' % util.int2ip(nrid))

        elif ospf_type == 5:
            LOG.debug('[Receiver] Received a LSAck from %s.' % util.int2ip(nrid))
            self.ism.ai.oi.stat.recv_lsack_count += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if nrid in self.nsm_list:
                    self.nsm_list[nrid].fp.check_lsack(pkt)
                    self.ism.ai.oi.stat.total_handled_packet_count += 1
                else:
                    LOG.warn('[Receiver] LSAck from %s not handled.' % util.int2ip(nrid))

        else:
            LOG.error('[Error] Wrong OSPF packet type.')
            pass

    def _handle_lsu(self, nrid, pkt):
        self.nsm_list[nrid].fp.check_lsu(pkt)
