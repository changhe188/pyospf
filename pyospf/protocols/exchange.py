#!/usr/bin/env python
# -*- coding:utf-8 -*-


from dpkt.ospf import OSPF

from pyospf.basic.ospfPacket import *
from pyospf.basic.ospfSock import OspfSock
from pyospf.protocols.protocol import *
from pyospf.utils.timer import Timer
from pyospf.basic.constant import *


class ExchangeProtocol(OspfProtocol):

    def __init__(self, nsm):

        OspfProtocol.__init__(self)

        self.init = 0
        self.more = 0
        self.ms = 0
        self._rls_last_dd_timer = None

        self.nsm = nsm
        self.dst = ALL_SPF_ROUTER   # by default

        if self.nsm.ism.link_type == 'Broadcast':
            if self.nsm.ism.drip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drip)
            if self.nsm.ism.bdrip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrip)
        elif self.nsm.ism.link_type == 'Point-to-Point':
            self.dst = util.int2ip(self.nsm.src)
        else:
        #TODO: if link type is virtual or others, set dst specific.
            pass

        #ospf socket
        self._sock = OspfSock()
        self._sock.bind(self.nsm.ism.ip_intf_addr)

    def __del__(self):
        self._sock.close()

    def set_dd_options(self):
        dolist = list(util.int2bin(self.nsm.dd_flags))
        self.init, self.more, self.ms = dolist[-3], dolist[-2], dolist[-1]

    def gen_dd(self, lsa=None):
        #In dd packet, the mtu is 1500 by default, but in virtual link, mtu is must set to 0
        #TODO: set virtual link mtu
        dd = DBDesc(
            mtu=self.nsm.ism.mtu,
            ddoptions=self.nsm.dd_flags,
            options=self.options,
            ddseq=self.nsm.dd_seqnum,
        )

        #TODO: unimplemented to send probe's dd
        if not lsa is None:
            pass

        ospf_packet = OSPF(
            v=self.version,
            type=2,             # 2 for dd
            area=self.area,
            len=len(dd)+len(OSPF()),
            router=self.rid,
            data=dd
        )

        return str(ospf_packet)

    def check_dd(self, pkt):
        """
        check received dd packet,
        return True means the packet is handled correctly,
        return False means the packet is not in right procedure
        """

        seq = pkt['V']['V']['DDSEQ']
        mss, i, m = pkt['V']['V']['MS'], pkt['V']['V']['INIT'], pkt['V']['V']['MORE']
        r, mtu = pkt['V']['RID'], pkt['V']['V']['MTU']
        opt = pkt['V']['V']['OPTS']

        last_ospf_opt = self.nsm.options  # save current ospf options
        self.nsm.options = opt   # update nsm ospf options

        tmp_last_recv = None      # save last recv packet
        if self.nsm.last_recv != (seq, i, m, mss):
            tmp_last_recv = self.nsm.last_recv
            self.nsm.last_recv = (seq, i, m, mss)

        #check mtu, if neighbor's mtu greater than our interface, drop it
        if self.nsm.ism.mtu < mtu:
            LOG.warn('[Exchange] Deny for bigger MTU.')
            return False

        if self.nsm.state == NSM_STATE['NSM_Down'] or self.nsm.state == NSM_STATE['NSM_Attempt']:
            LOG.warn('[Exchange] Deny for inappropriate state.')
            return False
        elif self.nsm.state == NSM_STATE['NSM_Init']:
            self.nsm.fire('NSM_TwoWayReceived')
            return False
        elif self.nsm.state == NSM_STATE['NSM_TwoWay']:
            LOG.warn('[Exchange] Ignore for inappropriate state.')
            return False

        elif self.nsm.state == NSM_STATE['NSM_ExStart']:
            #Negotiate DD exchange
            if mss == 1 and m == 1 and i == 1 and r > self.rid:
                self.init = 0
                self.more = 1
                self.ms = 0     # set myself slave, use master dd seq number

                self.nsm.dd_seqnum = pkt['V']['V']['DDSEQ']
                self.nsm.dd_flags = 4 * self.init + 2 * self.more + self.ms
                LOG.info('[NSM] Event: NSM_NegotiationDone')
                LOG.info('[NSM] We are slave.')
                self.nsm.fire('NSM_NegotiationDone')
                return True
            elif mss == 0 and i == 0 and r < self.rid:
                self.init = 0
                self.more = 1
                self.ms = 1     # set myself master, use my dd seq number
                self.nsm.dd_seqnum += 1

                self.nsm.dd_flags = 4 * self.init + 2 * self.more + self.ms
                LOG.info('[NSM] Event: NSM_NegotiationDone')
                LOG.info('[NSM] We are master.')
                self.nsm.fire('NSM_NegotiationDone')
                if m == 0:
                    self.nsm.fire('NSM_ExchangeDone')
                return True
            else:
                LOG.warn('[Exchange] Ignore for inappropriate dd options.')
                return False

        if self.nsm.state == NSM_STATE['NSM_Exchange']:

            if (seq, i, m, mss) == tmp_last_recv:
                if self.ms == 1:
                    LOG.warn('[Exchange] Duplicate DD packet, drop as master.')
                    return False
                else:
                    #retransmit the last send packet
                    LOG.warn('[Exchange] Duplicate DD packet, retransmit as slave.')
                    self.send_dd(self.nsm.last_send)
                    return False
            #check whether master/slave bit match or init bit is set unexpected
            if mss == self.ms or i == 1:
                LOG.warn('[Exchange] DD packet wrong options.')
                self.nsm.fire('NSM_SeqNumberMismatch')
                return False

            #check whether ospf option is as same as the last received ospf packet
            if not last_ospf_opt is None:
                if last_ospf_opt != pkt['V']['V']['OPTS']:
                    LOG.warn('[Exchange] DD packet OSPF options are not same as the last received packet.')
                    self.nsm.fire('NSM_SeqNumberMismatch')
                    return False

            #new recv dd packet is not last recv dd packet, get its lsa header
            if not self._get_lsa(pkt):
                #if there's some thing wrong in lsa header, fire SeqNumMismatch
                LOG.error('[Exchange] DD packet has wrong LSA header.')
                self.nsm.fire('NSM_SeqNumberMismatch')
                return False

            #when more bit is 0, exchange stop, goto loading state
            if m == 0:
                if self.ms == 0:    # If we are slave, send dd as reply.
                    self.nsm.dd_seqnum = seq
                    #all pass checked, send my dd to neighbor
                    self.exchange()
                self.nsm.fire('NSM_ExchangeDone')
            else:
                #if probe is master, ddseq + 1; if slave, set ddseq to master ddseq
                if self.ms == 1:
                    self.nsm.dd_seqnum += 1
                else:
                    self.nsm.dd_seqnum = seq
                #all pass checked, send my dd to neighbor
                self.exchange()

            return True

        elif self.nsm.state == NSM_STATE['NSM_Loading'] or self.nsm.state == NSM_STATE['NSM_Full']:

            #check whether ospf option is as same as the last received ospf packet
            if not last_ospf_opt is None:
                if last_ospf_opt != pkt['V']['V']['OPTS']:
                    LOG.warn('[Exchange] DD packet OSPF options are not same as the last received packet.')
                    self.nsm.fire('NSM_SeqNumberMismatch')
                    return False
            #Unexpected init bit
            if i == 1:
                LOG.error('[Exchange] Unexpected init bit in DD packet.')
                self.nsm.fire('NSM_SeqNumberMismatch')
                return False

            if self.ms == 1:
                LOG.error('[Exchange] Duplicate DD packet, drop as master.')
                return False
            else:
                #retransmit the last send packet
                if self.nsm.last_send is None:
                    LOG.error('[Exchange] Cannot retransmit last DD packet.')
                    self.nsm.fire('NSM_SeqNumberMismatch')
                    return False
                LOG.warn('[Exchange] Duplicate DD packet, retransmit as slave.')
                self.send_dd(self.nsm.last_send)
                return True
        else:
            pass

    def send_dd(self, pkt):
        if self.nsm.ism.link_type == 'Broadcast' and self.dst != self.nsm.ism.drip and self.dst != self.nsm.ism.bdrip:
            if self.nsm.ism.drip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drip)
            if self.nsm.ism.bdrip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrip)
        self._sock.conn(self.dst)

        LOG.info('[Exchange] Send DD to %s.' % self.dst)
        self._sock.sendp(pkt)

        self.nsm.ism.ai.oi.stat.send_dd_count += 1
        self.nsm.ism.ai.oi.stat.total_send_packet_count += 1

        if self.nsm.state == NSM_STATE['NSM_Loading'] or self.nsm.state == NSM_STATE['NSM_Full']:
            self.nsm.last_send = pkt    # save the last sent packet

            #start a timer to wait dead interval to release the last recv packet
            if self._rls_last_dd_timer is None or self._rls_last_dd_timer.is_stop():
                self._rls_last_dd_timer = Timer(self.nsm.ism.dead_interval, self._rls_last_dd, once=True)
                self._rls_last_dd_timer.start()
            else:
                self._rls_last_dd_timer.reset()

    def _rls_last_dd(self):
        LOG.debug('[Exchange] Release last send DD packet.')
        self.nsm.last_send = None

    def _get_lsa(self, pkt):
        aid = pkt['V']['AID']
        lsa_hdr_list = pkt['V']['V']['LSAS']
        for lsah in lsa_hdr_list.keys():
            tp, lsid, adv, seq = lsa_hdr_list[lsah]['T'],\
                                 lsa_hdr_list[lsah]['LSID'],\
                                 lsa_hdr_list[lsah]['ADVRTR'],\
                                 lsa_hdr_list[lsah]['LSSEQNO'],\

            #generate lsa key according to lsa type.
            if tp == 5:
                #check if a type-5 lsa into a stub area, return false
                if self.nsm.ism.options['E'] == 0:
                    return False
                lsakey = (tp, lsid, adv)
            else:
                lsakey = (tp, aid, lsid, adv)

            lsalist = self.nsm.ism.ai.oi.lsdb.lookup_lsa_list(tp)
            if not lsalist is None:
                lsa = self.lookup_lsa(lsakey, lsalist)
                if lsa is None:
                    self.nsm.ls_req.append(lsakey)
                elif lsa['H']['LSSEQNO'] < seq:
                    #the lsa in dd is newer than lsa in the database
                    self.nsm.ls_req.append(lsakey)
                else:
                    continue
            #if did not find the lsa list
            else:
                LOG.error('[Exchange] Wrong LSA type in DD.')
                return False
        return True

    def exchange(self):
        #TODO: The probe always set more bit to 0 when exchange. Need to modify if we want to send probe's DD summary.
        lsa = self.nsm.db_sum
        tosend = lsa
        self.more = 0   # set more bit 0
        self.nsm.dd_flags = 4 * int(self.init) + 2 * int(self.more) + int(self.ms)
        LOG.debug('[Exchange] DD flag is %s.' % self.nsm.dd_flags)

        self.send_dd(self.gen_dd(tosend))

    def gen_lsr(self, rq):
        pkts = []
        maxlsa = 100
        more = True

        #In each LSR packet, it contains 100 lsa headers at max
        while more:
            if len(rq) - maxlsa > 0:
                lsas, rq = rq[:maxlsa], rq[maxlsa:]
            else:
                lsas = rq
                more = False

            lsrdata = []
            lsrlen = len(lsas) * len(LSR())

            for r in lsas:
                if r[0] == 5:
                    lsrdata.append(str(LSR(
                        lstype=r[0],
                        lsid=r[1],
                        adv=r[2]
                    )))
                else:
                    lsrdata.append(str(LSR(
                        lstype=r[0],
                        lsid=r[2],
                        adv=r[3]
                    )))

            ospf_packet = OSPF(
                v=self.version,
                type=3,             # 3 for lsr
                area=self.area,
                len=lsrlen + len(OSPF()),
                router=self.rid,
                data=''.join(lsrdata)
            )

            pkts.append(str(ospf_packet))
        return pkts

    def send_lsr(self, pkts):
        if self.nsm.ism.link_type == 'Broadcast' and self.dst != self.nsm.ism.drip and self.dst != self.nsm.ism.bdrip:
            if self.nsm.ism.drip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drip)
            if self.nsm.ism.bdrip == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrip)
        LOG.debug('[Exchange] Send LSR to %s.' % self.dst)
        self._sock.conn(self.dst)
        for p in pkts:
            self._sock.sendp(p)

            self.nsm.ism.ai.oi.stat.send_lsr_count += 1
            self.nsm.ism.ai.oi.stat.total_send_packet_count += 1

    def check_lsr(self, pkt):
        """
        The probe doesn't need to receive LSR
        """
        pass
