#!/usr/bin/env python
# -*- coding:utf-8 -*-

import datetime

from dpkt.ospf import OSPF

from pyospf.core.neighborStateMachine import *
from pyospf.core.basics.ospfPacket import *
from pyospf.core.basics.ospfSock import *
from pyospf.core.protocols.protocol import *


class FloodProtocol(OspfProtocol):

    def __init__(self, nsm):

        OspfProtocol.__init__(self)
        self.nsm = nsm

        #ospf socket
        self._sock = OspfSock()
        self._sock.bind(self.nsm.ism.ipIntfAddr)

    def __del__(self):
        self._sock.close()

    def check_lsu(self, pkt):
        """
        Check LSU according to RFC chap. 13
        """
        if self.nsm.state == NSM_STATE['NSM_Exchange'] or\
           self.nsm.state == NSM_STATE['NSM_Loading'] or\
           self.nsm.state == NSM_STATE['NSM_Full']:

            #check lsa area
            aid = pkt['V']['AID']
            if aid != util.ip2int(self.nsm.ism.areaId):
                LOG.warn('[Flood] LSU from wrong area %s.' % util.int2ip(aid))
                return

            lsas = pkt['V']['V']['LSAS']
            uniAck = []

            for lsa in lsas.keys():
                #check lsa chksum, step 1, this step has done in ospfParser

                #print '**OPTS',lsas[lsa]['H']['OPTS']

                #check allowed lsa type, step 2
                tp = lsas[lsa]['H']['T']
                #lsList = None
                if tp not in ALLOW_LS_TYPE:
                    LOG.warn('[Flood] Nonsupport LS type.')
                    continue
                else:
                    lsList = self.lookup_lsa_list(tp, self.nsm.ism.ai.oi)

                #if type=5, check area type. if area is stub, drop it. step 3.
                if tp == 5 and self.nsm.options['E'] == 0:
                    LOG.warn('[Flood] Type-5 LSA in stub area, drop it.')
                    continue
                #if type=7, check option.
                if tp == 7 and self.nsm.options['NP'] == 0:
                    LOG.warn('[Flood] Type-7 LSA in not NSSA area, drop it.')
                    continue
                if tp in [9, 10, 11] and self.nsm.options['O'] == 0:
                    LOG.warn('[Flood] Opaque LSA not supported, drop it.')
                    continue
                #if type=11, check area type. if area is stub, drop it. step 3.
                if tp == 11 and self.nsm.options['E'] == 0:
                    LOG.warn('[Flood] Type-11 LSA in stub area, drop it.')
                    continue

                #check lsu age, step 4
                id, adv = lsas[lsa]['H']['LSID'], lsas[lsa]['H']['ADVRTR']
                #generate lsa key,
                # for type-5, ls key is (type, lsid, adv-rt),
                # for other types, ls key is (type, areaid, lsid, adv-rt)
                if tp == 5:
                    ls = (tp, id, adv)
                else:
                    ls = (tp, aid, id, adv)
                age = lsas[lsa]['H']['AGE']

                if age == MAXAGE and\
                   ls not in lsList.keys() and\
                   self.nsm.state != NSM_STATE['NSM_Exchange'] and\
                   self.nsm.state != NSM_STATE['NSM_Loading']:

                    #send lsack and continue to handle next lsa
                    LOG.info('[Flood] Received MAX age LSA %s. Send unicast LSAck.' % str(ls))

                    self._sock.conn(util.int2ip(self.nsm.src))
                    lsaHdr = {1: lsas[lsa]}
                    self.send_lsack(self.gen_lsack(lsaHdr))
                    del lsas[lsa]
                    continue

                #step 5
                existLsa = self.lookup_lsa(ls, lsList)

                if existLsa is None or self.judge_new_lsa(existLsa['H'], lsas[lsa]['H']) == lsas[lsa]['H']:
                    #check whether this lsa is added in lsList in MinLSArrival, if yes, drop it.
                    if (existLsa is not None) and self.judge_new_lsa(existLsa['H'], lsas[lsa]['H']) == lsas[lsa]['H']:
                        #step 5a
                        existLsaTimestamp = util.strptime(datetimeLock, existLsa['TIMESTAMP'])
                        if abs((existLsaTimestamp - datetime.datetime.now()).seconds) < MIN_LS_ARRIVAL:
                            LOG.debug('[Flood] LSA received in MinLSArrival.')
                            continue
                        #TODO: flood this lsa to subset of the interfaces. step 5b
                        else:
                            pass

                    #remove this lsa in all neighbors' ls_rxmt. step 5c
                    for rid in self.nsm.ism.hp.nsmList:
                        if self.nsm.ism.hp.nsmList[rid].ls_rxmt.count(lsas[lsa]) > 0:
                            self.nsm.ism.hp.nsmList[rid].ls_rxmt.remove(lsas[lsa])

                    #add timestamp and add this lsa to ls list. step 5d
                    lsas[lsa]['TIMESTAMP'] = util.current_time()
                    lsas[lsa]['AREA'] = aid
                    lsdbLock.acquire()
                    if ls in lsList and age == MAXAGE:
                        #if the age is MAXAGE, delete this lsa in the list. Attention: this is not the rule in rfc.
                        LOG.info('[Flood] Received LSA %s of MAXAGE. Delete it in LSDB.' % str(ls))
                        del lsList[ls]
                        #send DEL message to backend immediately.
                        self.nsm.ism.ai.oi.save_lsa_del(lsas[lsa])
                        self.nsm.ism.ai.oi.send_del_lsa()
                    else:
                        lsList[ls] = lsas[lsa]
                        self.nsm.ism.ai.oi.save_lsa_update(lsas[lsa])
                    lsdbLock.release()

                    #remove the lsa in ls_req if it exists in it. Attention: this is not the rule in rfc.
                    if ls in self.nsm.ls_req:
                        self.nsm.ls_req.remove(ls)
                        if len(self.nsm.ls_req) == 0 and not self.nsm._lsrResendTimer.isStop():
                            self.nsm._lsrResendTimer.stop()
                            #send lsack to neighbor
                            #self.send_lsack(self.gen_lsack(lsas))
                            #change nsm to full state
                            if self.nsm.state != NSM_STATE['NSM_Full']:
                                self.nsm.fire('NSM_LoadingDone')
                                continue

                    #TODO: maybe need to send lsack to receiver. step 5e

                    #if the lsa is self-originated, may need to do some special work. step 5f
                    # As a probe, it will has no self-originated LSA. Skip this.

                #If lsa exists and the local one is newer or equal to the received lsa.
                else:
                    #if this lsa is in ls_req, throws a BadLSReq. step 6
                    if ls in self.nsm.ls_req:
                        LOG.info('[NSM] Event: NSM_BadLSReq')
                        self.nsm.fire('NSM_BadLSReq')
                        return
                    #if the existLSA is equal to this lsa, do as follow. step 7
                    if not self.judge_new_lsa(existLsa['H'], lsas[lsa]['H']):
                        #step 7a
                        if lsas[lsa] in self.nsm.ls_rxmt:
                            #implied acknowledgment
                            self.nsm.ls_rxmt.remove(lsas[lsa])
                        #need to send lsack to neighbor, step 7b
                        else:
                            uniAck.append(lsas[lsa])
#                            self.s.conn(utils.int2ip(self.nsm.d_router))
#                            lsaHdr = {1:lsas[lsa]}
#                            self.s.sendp(self.gen_lsack(lsaHdr))
                            del lsas[lsa]
                        continue

                    #if the existLSA is more recent, do as follow. step 8
                    elif self.judge_new_lsa(existLsa['H'], lsas[lsa]['H']) == existLsa['H']:
                        if existLsa['H']['AGE'] == MAXAGE and existLsa['H']['LSSEQNO'] == MAX_SEQ_NO:
                            LOG.warn('[Flood] MaxSequenceNumber LSA, drop it.')
                            del lsas[lsa]
                        else:
                            #Send a lsu to the neighbor if it didn't be sent in MinLSArrival,
                            # This not necessary in probe, so we send lsack to neighbor.
                            pass

            #send lsack after handling all lsa
            else:
                if len(self.nsm.ls_req) > 0:
                    LOG.debug('[Exchange] Still have %s LSA to request.' % len(self.nsm.ls_req))
                if len(uniAck) != 0:
                    LOG.debug('[Flood] Send LSAck to %s.' % util.int2ip(self.nsm.src))
                    uniAcks = {}
                    for indexAck in range(0, len(uniAck)):
                        uniAcks[indexAck + 1] = uniAck[indexAck]
                    self._sock.conn(util.int2ip(self.nsm.src))
                    self.send_lsack(self.gen_lsack(uniAcks))

                if len(lsas) != 0:
                    if self.nsm.ism.linkType == 'Broadcast':
                        dst = ALL_D_ROUTER
                    elif self.nsm.ism.linkType == 'Point-to-Point':
                        dst = ALL_SPF_ROUTER
                    else:
                        dst = ALL_SPF_ROUTER
                    LOG.debug('[Flood] Send multicast LSAck to %s.' % dst)
                    self._sock.conn(dst)
                    self.send_lsack(self.gen_lsack(lsas))

                #send message to backend server when nsm is in full state.
                if self.nsm.state == NSM_STATE['NSM_Full']:
                    self.nsm.ism.ai.oi.send_put_lsa()
        else:
            LOG.warn('[Flood] NSM is under Exchange state, drop this LSU.')
            return

    def check_lsack(self, pkt):
        pass

    def send_lsack(self, pkt):
        self._sock.sendp(pkt)

        self.nsm.ism.ai.oi.sendLSAckCount += 1
        self.nsm.ism.ai.oi.totalSendPacketCount += 1

    def gen_lsack(self, lsas):
        lsackData = []
        for lsa in lsas.keys():
            hdr = lsas[lsa]['H']
            lsackData.append(str(LSAHeader(
                age=hdr['AGE'],
                options=self.calc_ospf_options(hdr['OPTS']),
                type=hdr['T'],
                id=hdr['LSID'],
                adv=hdr['ADVRTR'],
                seq=hdr['LSSEQNO'],
                sum=hdr['CKSUM'],
                len=hdr['L']
            )))

        ospfData = ''.join(lsackData)
        ospfPacket = OSPF(
            v=self.version,
            type=5,             # 5 for lsack
            area=self.area,
            len=len(ospfData)+len(OSPF()),
            router=self.rid,
            data=ospfData
        )

        return str(ospfPacket)
