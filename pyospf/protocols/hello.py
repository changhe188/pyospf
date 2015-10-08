#!/usr/bin/env python
# -*- coding:utf-8 -*-

from dpkt.ospf import OSPF

from pyospf.core.neighborStateMachine import *
from pyospf.core.basics.ospfPacket import *
from pyospf.core.basics.ospfSock import *
from pyospf.core.protocols.protocol import *
from pyospf.utils import util


class HelloProtocol(OspfProtocol):

    def __init__(self, ism):

        OspfProtocol.__init__(self)

        self.netmask = 0
        self.linkType = None
        self.drIp = 0
        self.bdrIp = 0

        self.ism = ism
        self.nsmList = ism.nbrList

        #ospf socket
        self._sock = OspfSock()
        self._sock.bind(self.ism.ipIntfAddr)
        self._sock.conn(ALL_SPF_ROUTER)

    def __del__(self):
        self._sock.close()

    def set_conf(self, v, hi, di, r, a, m, o, t, dr, bdr):
        self.version = v
        self.helloInterval = hi
        self.deadInterval = di
        self.area = util.ip2int(a)
        self.rid = util.ip2int(r)
        self.netmask = util.ip2int(m)
        self.options = self.calc_ospf_options(o)
        self.linkType = t
        self.drIp = dr
        self.bdrIp = bdr

    def send_hello(self, pkt):
        LOG.debug('[Hello] Send Hello')
        self._sock.sendp(pkt)
        self.ism.ai.oi.sendHelloCount += 1
        self.ism.ai.oi.totalSendPacketCount += 1

    def gen_hello(self):

        hello = Hello(
            hellointerval=self.helloInterval,
            deadinterval=self.deadInterval,
            mask=self.netmask,
            options=self.options,
            router=self.drIp,
            backup=self.bdrIp
        )
        for nbr in self.ism.neighbor:
            hello.data += str(HelloNeighbor(neighbor=nbr))

        ospfPacket = OSPF(
            v=self.version,
            type=1,             # 1 for hello
            area=self.area,
            len=len(hello)+len(OSPF()),
            router=self.rid,
            data=hello
        )

        return str(ospfPacket)

    def check_hello(self, pkt):
        """
        check neighbor hello contents match or not
        """
        ver = pkt['V']['VER']
        nrid = pkt['V']['RID']
        aid = pkt['V']['AID']
        net = pkt['V']['V']['NETMASK']
        hi = pkt['V']['V']['HELLO']
        di = pkt['V']['V']['DEAD']
        opt = pkt['V']['V']['OPTS']

        if ver != self.version:
            # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'VERSION_MISMATCH',
            #     self.ism.ai.oi.processId,
            #     [util.int2ip(nrid), self.version, ver]
            # ))
            LOG.warn('[Hello] Router %s version %d mismatch.' % (util.int2ip(nrid), ver))
            return False

        #area check has be handled in ospf receiver
        # if aid != self.area:
        #     self.ism.ai.oi.msgHandler.record_event(Event.str_event(
        #         'AREA_MISMATCH',
        #         self.ism.ai.oi.processId,
        #         [util.int2ip(nrid), util.int2ip(self.area), util.int2ip(aid)]
        #     ))
        #     LOG.warn('[Hello] Router %s area ID %s mismatch.' % (util.int2ip(nrid), util.int2ip(aid)))
        #     return False

        if hi != self.helloInterval:
            # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'HELLO_TIMER_MISMATCH',
            #     self.ism.ai.oi.processId,
            #     [util.int2ip(nrid), self.helloInterval, hi]
            # ))
            LOG.warn('[Hello] Router %s hello interval %d mismatch.' % (util.int2ip(nrid), hi))
            return False
        if di != self.deadInterval:
            # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'DEAD_TIMER_MISMATCH',
            #     self.ism.ai.oi.processId,
            #     [util.int2ip(nrid), self.deadInterval, di]
            # ))
            LOG.warn('[Hello] Router %s dead interval %d mismatch.' % (util.int2ip(nrid), di))
            return False
        if self.linkType != 'Point-to-Point' and self.linkType != 'Virtual':
        #If linkType is p2p or virtual link, ignore this check
            if net != self.netmask:
                # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
                #     'NETMASK_MISMATCH',
                #     self.ism.ai.oi.processId,
                #     [util.int2ip(nrid), util.int2ip(self.netmask), util.int2ip(net)]
                # ))
                LOG.warn('[Hello] Router %s netmask %s mismatch.' % (util.int2ip(nrid), util.int2ip(net)))
                return False

        if self.options >> 1 & 0x1 != opt['E']:
            # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'OPT_MISMATCH',
            #     self.ism.ai.oi.processId,
            #     [util.int2ip(nrid), self.options, opt]
            # ))
            LOG.warn('[Hello] Router %s E-bit option %s mismatch.' % (util.int2ip(nrid), opt['E']))
            return False
        if self.options >> 3 & 0x1 != opt['NP']:
            # self.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'OPT_MISMATCH',
            #     self.ism.ai.oi.processId,
            #     [util.int2ip(nrid), self.options, opt]
            # ))
            LOG.warn('[Hello] Router %s NP-bit option %s mismatch.' % (util.int2ip(nrid), opt['NP']))
            return False
        #TODO: check other options

        #Pass check, add to active neighbor
        # neighborLock.acquire()
        if not nrid in self.ism.neighbor:
            LOG.info('[Hello] Add new active neighbor %s.' % util.int2ip(nrid))
            self.ism.neighbor.append(nrid)

            #Meanwhile, create an NSM for this router.
            if not self.nsmList.has_key(nrid):
                self.nsmList[nrid] = NSM(self.ism, nrid, pkt)

        LOG.debug('[NSM] %s Event: NSM_PacketReceived.' % util.int2ip(nrid))
        self.nsmList[nrid].fire('NSM_PacketReceived')
        # neighborLock.release()
        return True

    def check_active_router(self, pkt):
        activeNrid = pkt['V']['V']['NBORS']
        nrid = pkt['V']['RID']

        if self.rid in activeNrid:
            LOG.debug('[NSM] %s Event: NSM_TwoWayReceived.' % util.int2ip(nrid))
            self.nsmList[nrid].fire('NSM_TwoWayReceived')
            return True
        else:
            LOG.debug('[NSM] %s Event: NSM_OneWayReceived' % util.int2ip(nrid))
            LOG.debug('[NSM] %s state is %s.' % (util.int2ip(nrid), self.nsmList[nrid].state))
            if self.nsmList[nrid].state >= NSM_STATE['NSM_TwoWay']:
                #This is not in RFC. When probe received hello without itself, make adj down.
                LOG.info('[NSM] One way state. Reset adjacency with router %s.' % util.int2ip(nrid))
                self.nsmList[nrid].reset()
            self.nsmList[nrid].fire('NSM_OneWayReceived')
            return False

    def get_dr_bdr(self, pkt):
        nrid = pkt['V']['RID']
        LOG.debug('[NSM] %s state is %s.' % (util.int2ip(nrid), self.nsmList[nrid].state))
        if self.nsmList[nrid].state < NSM_STATE['NSM_TwoWay']:
            return
        else:
            srcip = pkt['H']['SRC']
            dr = pkt['V']['V']['DESIG']
            bdr = pkt['V']['V']['BDESIG']
            prio = pkt['V']['V']['PRIO']

            if self.drIp != dr:
                if dr == srcip or bdr == srcip:
                    self.drIp, self.bdrIp = dr, bdr
                    self.ism.drIp, self.ism.bdrIp = dr, bdr
                    LOG.debug('[ISM] DR/BDR found: %s, %s'
                                   % (util.int2ip(self.ism.drIp), util.int2ip(self.ism.bdrIp)))

                    LOG.info('[ISM] Event: ISM_BackupSeen.')
                    self.ism.fire('ISM_BackupSeen')

            #TODO: Also need to check prio, dr, bdr state to decide whether to fire a NeighborChange event
