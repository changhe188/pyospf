#!/usr/bin/env python
# -*- coding:utf-8 -*-


from dpkt.ospf import OSPF

from pyospf.core.basics.ospfPacket import *
from pyospf.core.basics.ospfSock import *
from pyospf.core.protocols.protocol import *
from pyospf.utils.timer import Timer
# from sender.event import *


class ExchangeProtocol(OspfProtocol):

    def __init__(self, nsm):

        OspfProtocol.__init__(self)

        self.init = 0
        self.more = 0
        self.ms = 0
        self._rlsLastDDTimer = None

        self.nsm = nsm
        self.dst = ALL_SPF_ROUTER   # by default

        if self.nsm.ism.linkType == 'Broadcast':
            if self.nsm.ism.drIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drIp)
            if self.nsm.ism.bdrIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrIp)
        elif self.nsm.ism.linkType == 'Point-to-Point':
            self.dst = util.int2ip(self.nsm.src)
        else:
        #TODO: if link type is virtual or others, set dst specific.
            pass

        #ospf socket
        self._sock = OspfSock()
        self._sock.bind(self.nsm.ism.ipIntfAddr)

    def __del__(self):
        self._sock.close()

    def set_dd_options(self):
        dolist = list(util.int2bin(self.nsm.ddFlags))
        self.init, self.more, self.ms = dolist[-3], dolist[-2], dolist[-1]

    def gen_dd(self, lsa=None):

        #In dd packet, the mtu is 1500 by default, but in virtual link, mtu is must set to 0
        #TODO: set virtual link mtu
        dd = DBDesc(
            mtu=self.nsm.ism.mtu,
            ddoptions=self.nsm.ddFlags,
            options=self.options,
            ddseq=self.nsm.ddSeqnum,
        )

        #TODO: unimplement to send probe's dd
        if lsa != None:
            pass

        ospfPacket = OSPF(
            v=self.version,
            type=2,             # 2 for dd
            area=self.area,
            len=len(dd)+len(OSPF()),
            router=self.rid,
            data=dd
        )

        return str(ospfPacket)

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

        #Attention: when receiving a dd, reset the inactive timer. This is not in rfc.
        # if not self.nsm._inactiveTimer is None:
#            self.nsm._inactiveTimer.reset()
#             pass

        lastOspfOpt = self.nsm.options  # save current ospf options
        self.nsm.options = opt   # update nsm ospf options

        tmpLastRecv = None      # save last recv packet
        if self.nsm.last_recv != (seq, i, m, mss):
            tmpLastRecv = self.nsm.last_recv
            self.nsm.last_recv = (seq, i, m, mss)

        #check mtu, if neighbor's mtu greater than our interface, drop it
        if self.nsm.ism.mtu < mtu:
            LOG.warn('[Exchange] Deny for bigger MTU.')
            # self.nsm.ism.ai.oi.msgHandler.record_event(Event.str_event(
            #     'MTU_MISMATCH',
            #     self.nsm.ism.ai.oi.processId,
            #     [util.int2ip(self.nsm.rtid), self.nsm.ism.mtu, mtu]
            # ))
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

                self.nsm.ddSeqnum = pkt['V']['V']['DDSEQ']
                self.nsm.ddFlags = 4 * self.init + 2 * self.more + self.ms
                LOG.info('[NSM] Event: NSM_NegotiationDone')
                LOG.info('[NSM] We are slave.')
                self.nsm.fire('NSM_NegotiationDone')
                return True
            elif mss == 0 and i == 0 and r < self.rid:
                self.init = 0
                self.more = 1
                self.ms = 1     # set myself master, use my dd seq number
                self.nsm.ddSeqnum += 1

                self.nsm.ddFlags = 4 * self.init + 2 * self.more + self.ms
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

            if (seq, i, m, mss) == tmpLastRecv:
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
            if not lastOspfOpt is None:
                if lastOspfOpt != pkt['V']['V']['OPTS']:
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
                    self.nsm.ddSeqnum = seq
                    #all pass checked, send my dd to neighbor
                    self.exchange()
                self.nsm.fire('NSM_ExchangeDone')
            else:
                #if probe is master, ddseq + 1; if slave, set ddseq to master ddseq
                if self.ms == 1:
                    self.nsm.ddSeqnum += 1
                else:
                    self.nsm.ddSeqnum = seq
                #all pass checked, send my dd to neighbor
                self.exchange()

            return True

        elif self.nsm.state == NSM_STATE['NSM_Loading'] or self.nsm.state == NSM_STATE['NSM_Full']:

            #check whether ospf option is as same as the last received ospf packet
            if not lastOspfOpt is None:
                if lastOspfOpt != pkt['V']['V']['OPTS']:
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
        if self.nsm.ism.linkType == 'Broadcast' and self.dst != self.nsm.ism.drIp and self.dst != self.nsm.ism.bdrIp:
            if self.nsm.ism.drIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drIp)
            if self.nsm.ism.bdrIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrIp)
        self._sock.conn(self.dst)

        LOG.info('[Exchange] Send DD to %s.' % self.dst)
        self._sock.sendp(pkt)

        self.nsm.ism.ai.oi.sendDDCount += 1
        self.nsm.ism.ai.oi.totalSendPacketCount += 1

        if self.nsm.state == NSM_STATE['NSM_Loading'] or self.nsm.state == NSM_STATE['NSM_Full']:
            self.nsm.last_send = pkt    # save the last sent packet

            #start a timer to wait dead interval to release the last recv packet
            if self._rlsLastDDTimer is None or self._rlsLastDDTimer.isStop():
                self._rlsLastDDTimer = Timer(self.nsm.ism.deadInterval, self._rls_last_dd, once=True)
                self._rlsLastDDTimer.start()
            else:
                self._rlsLastDDTimer.reset()

    def _rls_last_dd(self):
        LOG.debug('[Exchange] Release last send DD packet.')
        self.nsm.last_send = None

    def _get_lsa(self, pkt):

        aid = pkt['V']['AID']
        lsaHdrList = pkt['V']['V']['LSAS']
        for lsah in lsaHdrList.keys():
            tp, id, adv, seq = lsaHdrList[lsah]['T'],\
                                 lsaHdrList[lsah]['LSID'],\
                                 lsaHdrList[lsah]['ADVRTR'],\
                                 lsaHdrList[lsah]['LSSEQNO'],\

            #generate lsa key according to lsa type.
            if tp == 5:
                #check if a type-5 lsa into a stub area, return false
                if self.nsm.ism.options['E'] == 0:
                    return False
                lsaKey = (tp, id, adv)
            else:
                lsaKey = (tp, aid, id, adv)

            lsaList = self.lookup_lsa_list(tp, self.nsm.ism.ai.oi)
            if not lsaList is None:
                lsa = self.lookup_lsa(lsaKey, lsaList)
                if lsa is None:
                    self.nsm.ls_req.append(lsaKey)
                elif lsa['H']['LSSEQNO'] < seq:
                    #the lsa in dd is newer than lsa in the database
                    self.nsm.ls_req.append(lsaKey)
                else:
                    continue
            #if did not find the lsa list
            else:
                LOG.error('[Exchange] Wrong LSA type in DD.')
                return False
        return True

    def exchange(self):
        #TODO: Attention: need to verify when to set more bit
        lsa = self.nsm.db_sum
        toSend = []
        lsaLength = 0
        if len(self.nsm.db_sum) < self.nsm.ism.mtu - 52:  # 52 means ip header length and ospf+dd header length
            self.more = 0   # set more bit 0
            self.nsm.ddFlags = 4 * int(self.init) + 2 * int(self.more) + int(self.ms)
        for h in lsa:
            lsaLength += 20
            if lsaLength > self.nsm.ism.mtu - 52:
                break
            toSend.append(h)
            self.nsm.db_sum.remove(h)

        self.send_dd(self.gen_dd(toSend))

    def gen_lsr(self, rq):
        pkts = []
        maxLsa = 100
        more = True

        #In each LSR packet, it contains 100 lsa headers at max
        while more:
            if len(rq) - maxLsa > 0:
                lsas, rq = rq[:maxLsa], rq[maxLsa:]
            else:
                lsas = rq
                more = False

            lsrData = []
            lsrLen = len(lsas) * len(LSR())

            for r in lsas:
                if r[0] == 5:
                    lsrData.append(str(LSR(
                        lstype=r[0],
                        lsid=r[1],
                        adv=r[2]
                    )))
                else:
                    lsrData.append(str(LSR(
                        lstype=r[0],
                        lsid=r[2],
                        adv=r[3]
                    )))

            ospfPacket = OSPF(
                v=self.version,
                type=3,             # 3 for lsr
                area=self.area,
                len=lsrLen + len(OSPF()),
                router=self.rid,
                data=''.join(lsrData)
            )

            pkts.append(str(ospfPacket))

        return pkts

    def send_lsr(self, pkts):
        if self.nsm.ism.linkType == 'Broadcast' and self.dst != self.nsm.ism.drIp and self.dst != self.nsm.ism.bdrIp:
            if self.nsm.ism.drIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.drIp)
            if self.nsm.ism.bdrIp == self.nsm.src:
                self.dst = util.int2ip(self.nsm.ism.bdrIp)
        LOG.debug('[Exchange] Send LSR to %s.' % self.dst)
        self._sock.conn(self.dst)
        for p in pkts:
            self._sock.sendp(p)

            self.nsm.ism.ai.oi.sendLSRCount += 1
            self.nsm.ism.ai.oi.totalSendPacketCount += 1

    def check_lsr(self, pkt):
        '''
        It seems probe doesn't need to receive LSR
        '''
        pass
