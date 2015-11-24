#!/usr/bin/env python
# -*- coding:utf-8 -*-

import datetime

from dpkt.ospf import OSPF

from pyospf.basic.constant import NSM_STATE
from pyospf.basic.ospfPacket import *
from pyospf.basic.ospfSock import OspfSock
from pyospf.protocols.protocol import *


class FloodProtocol(OspfProtocol):

    def __init__(self, nsm):

        OspfProtocol.__init__(self)
        self.nsm = nsm

        #ospf socket
        self._sock = OspfSock()
        self._sock.bind(self.nsm.ism.ip_intf_addr)

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
            if aid != util.ip2int(self.nsm.ism.area_id):
                LOG.warn('[Flood] LSU from wrong area %s.' % util.int2ip(aid))
                return

            lsas = pkt['V']['V']['LSAS']
            uniack = []
            tobe

            for lsa in lsas:
                #check lsa chksum, step 1, this step has done in ospfParser
                #check allowed lsa type, step 2
                tp = lsas[lsa]['H']['T']
                if tp not in ALLOW_LS_TYPE:
                    LOG.warn('[Flood] Nonsupport LS type.')
                    continue
                else:
                    lslist = self.nsm.ism.ai.oi.lsdb.lookup_lsa_list(tp)

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
                lsid, adv = lsas[lsa]['H']['LSID'], lsas[lsa]['H']['ADVRTR']
                #generate lsa key,
                # for type-5, ls key is (type, lsid, adv-rt),
                # for other types, ls key is (type, areaid, lsid, adv-rt)
                if tp == 5:
                    ls = (tp, lsid, adv)
                else:
                    ls = (tp, aid, lsid, adv)
                age = lsas[lsa]['H']['AGE']

                if age == MAXAGE and\
                   ls not in lslist.keys() and\
                   self.nsm.state != NSM_STATE['NSM_Exchange'] and\
                   self.nsm.state != NSM_STATE['NSM_Loading']:

                    #send lsack and continue to handle next lsa
                    LOG.info('[Flood] Received MAX age LSA %s. Send unicast LSAck.' % str(ls))

                    self._sock.conn(util.int2ip(self.nsm.src))
                    lsahdr = {1: lsas[lsa]}
                    self.send_lsack(self.gen_lsack(lsahdr))
                    continue

                #step 5
                exist_lsa = self.lookup_lsa(ls, lslist)

                if exist_lsa is None or self.judge_new_lsa(exist_lsa['H'], lsas[lsa]['H']) == lsas[lsa]['H']:
                    #check whether this lsa is added in lslist in MinLSArrival, if yes, drop it.
                    if (exist_lsa is not None) and self.judge_new_lsa(exist_lsa['H'], lsas[lsa]['H']) == lsas[lsa]['H']:
                        #step 5a
                        exist_lsa_timestamp = util.strptime(datetimeLock, exist_lsa['TIMESTAMP'])
                        if abs((exist_lsa_timestamp - datetime.datetime.now()).seconds) < MIN_LS_ARRIVAL:
                            LOG.debug('[Flood] LSA received in MinLSArrival.')
                            continue
                        #TODO: flood this lsa to subset of the interfaces. step 5b
                        else:
                            pass

                    #remove this lsa in all neighbors' ls_rxmt. step 5c
                    for rid in self.nsm.ism.hp.nsm_list:
                        if self.nsm.ism.hp.nsm_list[rid].ls_rxmt.count(lsas[lsa]) > 0:
                            self.nsm.ism.hp.nsm_list[rid].ls_rxmt.remove(lsas[lsa])

                    #add timestamp and add this lsa to ls list. step 5d
                    lsas[lsa]['TIMESTAMP'] = util.current_time_str()
                    lsas[lsa]['AREA'] = aid
                    self.nsm.ism.ai.oi.lsdb.lsdb_lock.acquire()
                    if ls in lslist and age == MAXAGE:
                        #if the age is MAXAGE, delete this lsa in the list. Attention: this is not the rule in rfc.
                        LOG.info('[Flood] Received LSA %s of MAXAGE. Delete it in LSDB.' % str(ls))
                        del lslist[ls]
                    else:
                        lslist[ls] = lsas[lsa]
                    self.nsm.ism.ai.oi.lsdb.lsdb_lock.release()

                    #remove the lsa in ls_req if it exists in it. Attention: this is not the rule in rfc.
                    if ls in self.nsm.ls_req:
                        self.nsm.ls_req.remove(ls)
                        if len(self.nsm.ls_req) == 0 and not self.nsm.lsr_resend_timer.is_stop():
                            self.nsm.lsr_resend_timer.stop()
                            #send lsack to neighbor
                            #self.send_lsack(self.gen_lsack(lsas))
                            #change nsm to full state
                            if self.nsm.state != NSM_STATE['NSM_Full']:
                                self.nsm.fire('NSM_LoadingDone')
                                continue

                    #TODO: maybe need to send lsack to receiver. step 5e
                    #if the lsa is self-originated, may need to do some special work. step 5f
                    #As a probe, it will has no self-originated LSA. Skip this.

                #If lsa exists and the local one is newer or equal to the received lsa.
                else:
                    #if this lsa is in ls_req, throws a BadLSReq. step 6
                    if ls in self.nsm.ls_req:
                        LOG.info('[NSM] Event: NSM_BadLSReq')
                        self.nsm.fire('NSM_BadLSReq')
                        return
                    #if the existLSA is equal to this lsa, do as follow. step 7
                    if not self.judge_new_lsa(exist_lsa['H'], lsas[lsa]['H']):
                        #step 7a
                        if lsas[lsa] in self.nsm.ls_rxmt:
                            #implied acknowledgment
                            self.nsm.ls_rxmt.remove(lsas[lsa])
                        #need to send lsack to neighbor, step 7b
                        else:
                            uniack.append(lsas[lsa])
                        continue

                    #if the existLSA is more recent, do as follow. step 8
                    elif self.judge_new_lsa(exist_lsa['H'], lsas[lsa]['H']) == exist_lsa['H']:
                        if exist_lsa['H']['AGE'] == MAXAGE and exist_lsa['H']['LSSEQNO'] == MAX_SEQ_NO:
                            LOG.warn('[Flood] MaxSequenceNumber LSA, drop it.')
                        else:
                            #Send a lsu to the neighbor if it didn't be sent in MinLSArrival,
                            # This not necessary in probe, so we send lsack to neighbor.
                            pass

            #send lsack after handling all lsa
            else:
                if len(self.nsm.ls_req) > 0:
                    LOG.debug('[Exchange] Still have %s LSA(s) to request.' % len(self.nsm.ls_req))
                if len(uniack) != 0:
                    LOG.debug('[Flood] Send LSAck to %s.' % util.int2ip(self.nsm.src))
                    uniacks = {}
                    for indexack in range(0, len(uniack)):
                        uniacks[indexack + 1] = uniack[indexack]
                    self._sock.conn(util.int2ip(self.nsm.src))
                    self.send_lsack(self.gen_lsack(uniacks))

                if len(lsas) != 0:
                    if self.nsm.ism.link_type == 'Broadcast':
                        dst = ALL_D_ROUTER
                    elif self.nsm.ism.link_type == 'Point-to-Point':
                        dst = ALL_SPF_ROUTER
                    else:
                        dst = ALL_SPF_ROUTER
                    LOG.debug('[Flood] Send multicast LSAck to %s.' % dst)
                    self._sock.conn(dst)
                    self.send_lsack(self.gen_lsack(lsas))
        else:
            LOG.warn('[Flood] NSM is under Exchange state, drop this LSU.')
            return

    def check_lsack(self, pkt):
        pass

    def send_lsack(self, pkt):
        self._sock.sendp(pkt)

        self.nsm.ism.ai.oi.stat.send_lsack_count += 1
        self.nsm.ism.ai.oi.stat.total_send_packet_count += 1

    def gen_lsack(self, lsas):
        lsackdata = []
        for lsa in lsas.keys():
            hdr = lsas[lsa]['H']
            lsackdata.append(str(LSAHeader(
                age=hdr['AGE'],
                options=self.convert_options_to_int(hdr['OPTS']),
                type=hdr['T'],
                id=hdr['LSID'],
                adv=hdr['ADVRTR'],
                seq=hdr['LSSEQNO'],
                sum=hdr['CKSUM'],
                len=hdr['L']
            )))

        ospfdata = ''.join(lsackdata)
        ospf_packet = OSPF(
            v=self.version,
            type=5,             # 5 for lsack
            area=self.area,
            len=len(ospfdata)+len(OSPF()),
            router=self.rid,
            data=ospfdata
        )
        return str(ospf_packet)
