#!/usr/bin/env python
# -*- coding:utf-8 -*-


import time

from basics.ospfParser import *
from basics.variable import *

from pyospf.utils import util
from pyospf.utils.threadpool import *


LOG = logging.getLogger(__name__)


class OspfReceiver(object):

    def __init__(self, ism, nsm_list):
        self.ism = ism
        self.nsmList = nsm_list

        #statistics
        self.totalReceivedPacketCount = 0
        self.recvHelloCount = 0
        self.recvDDCount = 0
        self.recvLSRCount = 0
        self.recvLSUCount = 0
        self.recvLSAckCount = 0
        self.totalHandledPacketCount = 0

        self.lsuHandlerPool = ThreadPool(1)


    def ospf_handler(self, data, timestamp):
        """
        Distinguish different kind OSPF packet, and call according functions
        """
        if not data:
            return
        LOG.debug('[Receiver] Received packet: %s:%f'
                  % (time.strftime('%H:%M', time.localtime(timestamp)), timestamp % 60))

        pkt = OspfParser.parse(data, probe=self.ism.ai.oi.processId, msgHandler=self.ism.ai.oi.msgHandler)
        # when use socket to receive packets, use this

        if pkt is None:
            LOG.error('[Receiver] Wrong Packet.')
            return False

        self.totalReceivedPacketCount += 1

        hdr = pkt['V']

        ospfType = hdr['TYPE']
        dst = pkt['H']['DST']
        nrid = hdr['RID']
        aid = hdr['AID']

        #check area ID to support RFC5185:
        if util.int2ip(aid) != self.ism.areaId:
            if self.ism.multiAreaCap:
                if not util.int2ip(aid) in self.ism.multiArea:
                    LOG.warn('[Receiver] Router %s area ID %s not in our area ID list.'
                             % (util.int2ip(nrid), util.int2ip(aid)))
            else:
                LOG.warn('[Receiver] Router %s area ID %s mismatch.'
                         % (util.int2ip(nrid), util.int2ip(aid)))
                # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
                #     'AREA_MISMATCH',
                #      self.ism.ai.oi.processId,
                #     [util.int2ip(nrid), self.ism.areaId, util.int2ip(aid)]
                # ))
            return

        if ospfType == 1:
            LOG.debug('[Receiver] Received a Hello.')
            self.recvHelloCount += 1
            neighborLock.acquire()
            if self.ism.hp.check_hello(pkt):
                self.totalHandledPacketCount += 1
                if self.ism.hp.check_active_router(pkt):
                    if self.ism.linkType != 'Point-to-Point':
                        self.ism.hp.get_dr_bdr(pkt)
            neighborLock.release()

        elif ospfType == 2:
            self.recvDDCount += 1
            LOG.debug('[Receiver] Received a Database Description from %s to %s.'
                           % (util.int2ip(nrid), util.int2ip(dst)))
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if self.nsmList.has_key(nrid):
                    self.nsmList[nrid].ep.check_dd(pkt)
                    self.totalHandledPacketCount += 1
                else:
                    LOG.debug('[Receiver] DD from %s not handled.' % util.int2ip(nrid))

        elif ospfType == 3:
            LOG.debug('[Receiver] Received a LSR from %s to %s.' %  (util.int2ip(nrid), util.int2ip(dst)))
            self.recvLSRCount += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if self.nsmList.has_key(nrid):
                    self.nsmList[nrid].ep.check_lsr(pkt)
                    self.totalHandledPacketCount += 1
                else:
                    LOG.debug('[Receiver] LSR from %s not handled.' % util.int2ip(nrid))

        elif ospfType == 4:
            LOG.debug('[Receiver] Received a LSU from %s to %s.' % (util.int2ip(nrid), util.int2ip(dst)))
            self.recvLSUCount += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if self.nsmList.has_key(nrid):
                    self.lsuHandlerPool.addTask(self._handle_lsu, (nrid, pkt))
                    self.totalHandledPacketCount += 1
                else:
                    LOG.warn('[Receiver] LSU from %s not handled.' % util.int2ip(nrid))

        elif ospfType == 5:
            LOG.debug('[Receiver] Received a LSAck from %s.' % util.int2ip(nrid))
            self.recvLSAckCount += 1
            if util.int2ip(dst) == ALL_D_ROUTER:
                LOG.warn('[Receiver] Not DR/BDR, drop it.')
            else:
                if self.nsmList.has_key(nrid):
                    self.nsmList[nrid].fp.check_lsack(pkt)
                    self.totalHandledPacketCount += 1
                else:
                    LOG.warn('[Receiver] LSAck from %s not handled.' % util.int2ip(nrid))

        else:
            LOG.error('[Error] Wrong OSPF packet type.')
            pass

    def _handle_lsu(self, nrid, pkt):
        self.nsmList[nrid].fp.check_lsu(pkt)

