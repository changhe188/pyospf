#!/usr/bin/env python
# -*- coding:utf-8 -*-


import time
import logging

from pyospf.protocols.flood import FloodProtocol
from pyospf.protocols.exchange import ExchangeProtocol
from pyospf.basic.constant import *

from pyospf.utils import util
from pyospf.utils.timer import Timer


LOG = logging.getLogger(__name__)


class NSM(object):
    """
    Neighbor State Machine
    :param ism: ISM objects.
    :param rtid: RouterID.
    :param pkt: coming hello packet.
    """

    def __init__(self, ism, rtid, pkt):
        #OSPF neighbor information
        self.state = NSM_STATE['NSM_Down']           # NSM status.
        self._inactive_timer = None
        self._dd_exstart_timer = None
        self.lsr_resend_timer = None

        self.dd_flags = 0        # DD bit flags. Slave or master.
        self.dd_seqnum = 0       # DD Sequence Number.

        #Last sent Database Description packet.
        self.last_send = None   # just the packet, not tuple
        #Timestemp when last Database Description packet was sent
        self.last_send_ts = 0   # not used
        #Last received Database Description packet.
        self.last_recv = tuple()     # pattern: (ddseq, init, more, ms)

        #LSA data.
        self.ls_rxmt = list()       # Link state retransmission list
        self.db_sum = list()        # Database summary list
        self.ls_req = list()        # Link state request list

        self.ism = ism
        self.rtid = rtid        # neighbor router id

        self.nsm = dict()

        #Neighbor Information from Hello.
        self.src = pkt['H']['SRC']
        self.options = pkt['V']['V']['OPTS']
        self.priority = pkt['V']['V']['PRIO']
        self.d_router = pkt['V']['V']['DESIG']
        self.bd_router = pkt['V']['V']['BDESIG']

        #inactive timer is equal to dead interval
        self.inactive_timer_interval = self.ism.dead_interval

        self.ep = ExchangeProtocol(self)
        self.fp = FloodProtocol(self)

        #register all nsm events
        for nsmEvent in NSM_EVENT.keys():
            if nsmEvent == 'NSM_PacketReceived':
                self.nsm[nsmEvent] = self._hello_received
            elif nsmEvent == 'NSM_TwoWayReceived':
                self.nsm[nsmEvent] = self._two_way_or_exstart
            elif nsmEvent == 'NSM_OneWayReceived':
                self.nsm[nsmEvent] = self._init
            elif nsmEvent == 'NSM_NegotiationDone':
                self.nsm[nsmEvent] = self._exchange
            elif nsmEvent == 'NSM_SeqNumberMismatch':
                self.nsm[nsmEvent] = self._seq_mismatch_or_bad_lsr
            elif nsmEvent == 'NSM_ExchangeDone':
                self.nsm[nsmEvent] = self._loading
            elif nsmEvent == 'NSM_BadLSReq':
                self.nsm[nsmEvent] = self._seq_mismatch_or_bad_lsr
            elif nsmEvent == 'NSM_LoadingDone':
                self.nsm[nsmEvent] = self._full
            else:
                continue

    def fire(self, event):
        self.nsm[event]()

    def reset(self):
        self.change_nsm_state('NSM_Down')
        if self._dd_exstart_timer is not None:
            self._dd_exstart_timer.stop()
            del self._dd_exstart_timer
        if self.lsr_resend_timer is not None:
            self.lsr_resend_timer.stop()
            del self.lsr_resend_timer
        self._dd_exstart_timer = None
        self.lsr_resend_timer = None

        self.ls_req = list()
        self.ls_rxmt = list()
        self.db_sum = list()
        self.last_recv = tuple()
        self.last_send = None
        self.last_send_ts = 0

        #Delete all LSA in LSDB
        self.ism.ai.oi.lsdb.empty_lsdb()

    def dead(self):
        neighborLock.acquire()
        self.reset()
        self.rtid = 0
        self.src = 0
        self.options = {'E': 0, 'MC': 0, 'L': 0, 'NP': 0, 'DC': 0, 'O': 0, 'DN': 0, 'Q': 0}
        self.priority = 0
        self.d_router = 0
        self.bd_router = 0
        if self._inactive_timer is not None:
            self._inactive_timer.stop()
            del self._inactive_timer
            self._inactive_timer = None
        LOG.info('[ISM] Event: ISM_NeighborChange')
        self.ism.fire('ISM_NeighborChange')
        neighborLock.release()

    def _hello_received(self):
        if self.state == NSM_STATE['NSM_Down']:
            self.change_nsm_state('NSM_Init')
            #start inactive timer
            if self._inactive_timer is None or self._inactive_timer.is_stop():
                self._inactive_timer = Timer(self.inactive_timer_interval, self.dead)
                self._inactive_timer.start()
                LOG.debug('[NSM] %s starts inactive timer.' % util.int2ip(self.rtid))
            else:
                self._inactive_timer.reset()
        else:
            self._inactive_timer.reset()

    def _attempt(self):
        """
        Only for nbma network
        """
        self.change_nsm_state('NSM_Attempt')

    def _init(self):
        if self.state == NSM_STATE['NSM_Init']:
            return
        self.change_nsm_state('NSM_Init')
        self.last_recv = tuple()
        self.last_send = None
        self.last_send_ts = 0
        self.ls_req = list()
        self.ls_rxmt = list()
        self.db_sum = list()
        if not self.lsr_resend_timer is None:
            self.lsr_resend_timer.stop()

    def _two_way_or_exstart(self):
        #whether become adjacent in broadcast, rfc 10.4
        if self.state == NSM_STATE['NSM_Init'] or self.state == NSM_STATE['NSM_TwoWay']:
            #need to make adjacency
            if self.ism.bdrip == self.src or self.ism.drip == self.src or self.ism.link_type == 'Point-to-Point':
                self.change_nsm_state('NSM_ExStart')

                #Generate dd_sum from each lsa list, and exception for virtual link and stub area.
                #But as a probe, we need not to send dd_sum.

                #start dd sync procedure
                self.dd_seqnum = int(time.time())
                self.dd_flags = 7    # set init bit, more bit, master bit
                self._send_dd()
                if self._dd_exstart_timer is None:
                    pass
                elif self._dd_exstart_timer.is_stop():
                    del self._dd_exstart_timer
                else:
                    self._dd_exstart_timer.stop()
                    del self._dd_exstart_timer
                self._dd_exstart_timer = Timer(self.ism.rxmt_interval, self._send_dd)
                self._dd_exstart_timer.start()

            #do not need to make adjacency
            else:
                if self.state == NSM_STATE['NSM_Init']:
                    #change to 2-way state
                    self.change_nsm_state('NSM_TwoWay')
                else:
                    #stay in 2-way state
                    pass

    def _exchange(self):
        self.change_nsm_state('NSM_Exchange')
        self._dd_exstart_timer.stop()
        self.fp.set_ospf_header(
            self.ism.version,
            self.ism.area_id,
            self.ism.rid,
            self.ism.options,
        )
        self.ep.exchange()

    def _loading(self):
        self.change_nsm_state('NSM_Loading')
        #start to send first lsr
        if len(self.ls_req) != 0:
            self._send_lsr(self.ls_req)
            self.lsr_resend_timer = Timer(self.ism.rxmt_interval, self._send_lsr, self.ls_req)
            self.lsr_resend_timer.start()
        else:
            self._full()

    def _full(self):
        self.change_nsm_state('NSM_Full')

    def _seq_mismatch_or_bad_lsr(self):
        LOG.warn('[NSM] %s sequence mismatch or bad LSR.' % util.int2ip(self.rtid))
        #make sure that all these are clear
        self.ls_req = list()
        self.ls_rxmt = list()
        self.db_sum = list()
        self.last_recv = tuple()
        self.last_send = None
        self.last_send_ts = 0

        self.change_nsm_state('NSM_ExStart')
        self.dd_flags = 7    # set init bit, more bit, master bit
        self.dd_seqnum = int(time.time())
        self._send_dd()
        if self._dd_exstart_timer is None:
            self._dd_exstart_timer = Timer(self.ism.rxmt_interval, self._send_dd)
            self._dd_exstart_timer.start()
        elif self._dd_exstart_timer.is_stop():
            del self._dd_exstart_timer
            self._dd_exstart_timer = Timer(self.ism.rxmt_interval, self._send_dd)
            self._dd_exstart_timer.start()
        else:
            self._dd_exstart_timer.reset()

    def _send_dd(self, lsa=None):

        self.ep.set_ospf_header(
            self.ism.version,
            self.ism.area_id,
            self.ism.rid,
            self.ism.options,
        )
        self.ep.set_dd_options()
        self.ep.send_dd(self.ep.gen_dd(lsa))

    def _send_lsr(self, lsr):
        self.ep.send_lsr(self.ep.gen_lsr(lsr))

    def change_nsm_state(self, newstate):
        LOG.info('[NSM] %s change state to %s.' % (util.int2ip(self.rtid), newstate))
        self.state = NSM_STATE[newstate]