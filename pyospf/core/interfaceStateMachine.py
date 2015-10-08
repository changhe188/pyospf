#!/usr/bin/env python
# -*- coding:utf-8 -*-

__author__ = 'changhe'

import datetime
import copy

from protocols.hello import *
from basics.variable import *
from pyospf.utils.timer import Timer


LOG = logging.getLogger(__name__)


class ISM(object):

    def __init__(self, ai):
        self.state = ISM_STATE['ISM_Down']

        self.infTransDelay = 1  # TODO: how to set?
        self.prior = 0          # set probe priority 0 permanently
        self.drIp = 0
        self.bdrIp = 0
        self.neighbor = list()      # save all neighbors rid
        self.nbrList = dict()       # save all neighbors' state(nsm), format: {nrid: nsm}
        self.outputCost = 0     # TODO: how to set?

        self.auType = 0         # TODO: Auth not implement
        self.auKey = None       # TODO: Auth not implement

        self._helloTimer = None
        self._electTimer = None
        self._lsaAgeTimer = None

        self.lsaAgeStep = 4     # check LSA age interval

        self.ai = ai

        self.version = 2
        self.rid = ai.oi.rid
        self.areaId = ai.area_id
        self.helloInterval = ai.oi.config['hello_interval']
        self.deadInterval = 4 * self.helloInterval
        self.ipIntfAddr = ai.oi.config['ip']
        self.ipInterMask = ai.oi.config['mask']
        self.linkType = ai.oi.config['link_type']
        self.options = ai.oi.config['options']
        self.rxmtInterval = ai.oi.config['rxmt_interval']
        self.mtu = ai.oi.config['mtu']

        self.multiAreaCap = False
        #rfc5185 multi-area adj support
        if ai.oi.config.has_key('multiArea'):
            self.multiAreaCap = True
            self.multiArea = ai.oi.config['multiArea']

        self.hp = HelloProtocol(self)
        self.ism = dict()

        #register all ism events
        for ismEvent in ISM_EVENT.keys():
            if ismEvent == 'ISM_InterfaceUp':
                self.ism[ismEvent] = self._interface_up
            elif ismEvent == 'ISM_InterfaceDown':
                self.ism[ismEvent] = self._down
            elif ismEvent == 'ISM_BackupSeen':
                self.ism[ismEvent] = self._dr_other
            elif ismEvent == 'ISM_WaitTimer':
                self.ism[ismEvent] = self._dr_other
            elif ismEvent == 'ISM_NeighborChange':
                self.ism[ismEvent] = self._nbr_change
            else:
                continue

        self.nbrDownFlag = False    # Whether neighbor down happened

    def fire(self, event):
        self.ism[event]()

    def _down(self):
        """
        To interface down state
        """
        if not self._helloTimer is None:
            self._helloTimer.stop()
            self._helloTimer = None
        if not self._lsaAgeTimer is None:
            self._lsaAgeTimer.stop()
            self._lsaAgeTimer = None
        if not self._electTimer is None:
            self._electTimer.stop()
            self._electTimer = None
        self.change_ism_state('ISM_Down')
        self.drIp = 0
        self.bdrIp = 0
        self.neighbor = list()
        self.nbrList = dict()

    def _interface_up(self):
        """
        Handler for interface up event
        """
        #point to point link, go to point_to_point state directly
        if self.linkType == 'Point-to-Point':
            self._point_to_point()
        #broadcast link, go to dr other state
        elif self.linkType == 'Broadcast':
            self._waiting()
        else:
            LOG.error('[ISM] Wrong Link Type.')
            return

    def _waiting(self):
        self.change_ism_state('ISM_Waiting')
        self._begin_hello()
        self._helloTimer = Timer(self.helloInterval, self._begin_hello)
        self._helloTimer.start()
        self._electTimer = Timer(self.deadInterval, self._elect_dr, once=True)
        self._electTimer.start()

    def loopback(self):
        """
        not used in probe
        """
        self.change_ism_state('ISM_Loopback')
        pass

    def _point_to_point(self):
        """
        send hello in p2p or virtual link
        """
        self.change_ism_state('ISM_PointToPoint')
        self._begin_hello()
        self._helloTimer = Timer(self.helloInterval, self._begin_hello)
        self._helloTimer.start()
        #start a timer to check all lsa age per lsaAgeStep second
        #TODO: this implementation should be checked.
        if self._lsaAgeTimer is None:
            self._lsaAgeTimer = Timer(self.lsaAgeStep, self._lsaAge)
            self._lsaAgeTimer.start()
            LOG.debug('[ISM] Start LSA age timer.')

    def _begin_hello(self):
        #start Hello Protocol
        self.hp.set_conf(
            self.version,
            self.helloInterval,
            self.deadInterval,
            self.rid,
            self.areaId,
            self.ipInterMask,
            self.options,
            self.linkType,
            self.drIp,
            self.bdrIp
        )
        self.hp.send_hello(self.hp.gen_hello())

    def _dr_other(self):
        """
        send hello in broadcast or nbma, not be dr
        """
        self.change_ism_state('ISM_DROther')
        if not self._electTimer.isStop():
            self._electTimer.stop()
        #start a timer to check all lsa age per lsaAgeStep second
        #TODO: this implementation should be checked.
        if self._lsaAgeTimer is None:
            self._lsaAgeTimer = Timer(self.lsaAgeStep, self._lsaAge)
            self._lsaAgeTimer.start()
            LOG.debug('[ISM] Start LSA age timer.')

    def _nbr_change(self):
        #Remove NSM which state is down
        tobeRemoved = []
        for nrid in self.nbrList:
            if self.nbrList[nrid].state == NSM_STATE['NSM_Down']:
                tobeRemoved.append(nrid)

        # neighborLock.acquire()
        for rm in tobeRemoved:
            if self.nbrList[rm].src == self.drIp:
                self.drIp = 0
            if self.nbrList[rm].src == self.bdrIp:
                self.bdrIp = 0
            del self.nbrList[rm]
            self.neighbor.remove(rm)
            LOG.info('[ISM] Neighbor %s delete.' % util.int2ip(rm))
        # neighborLock.release()

        if self.linkType == 'Broadcast':
            if not self._electTimer.isStop():
                self._electTimer.stop()
            self._elect_dr()

    def backup(self):
        """
        being bdr, probe cannot be bdr
        """
        self.change_ism_state('ISM_Backup')
        pass

    def dr(self):
        """
        being dr, probe cannot be dr
        """
        self.change_ism_state('ISM_DR')
        pass

    def _elect_dr(self):
        """
        dr election algorithm
        """
        #TODO: unimplement
        LOG.debug('[ISM] Election Finished.')
        if self.state == ISM_STATE['ISM_Waiting']:
            #Receive some cross-thread flag change, and then fire the event
            LOG.info('[ISM] Event: ISM_WaitTimer')
            self.fire('ISM_WaitTimer')
        else:
            self._dr_other()

    def change_ism_state(self, newState):
        LOG.info("[ISM] Change state to %s" % newState)
        self.state = ISM_STATE[newState]

    def _lsaAge(self):
        """
        Check all LSA age, and when LSA's age is MAXAGE, call aged handler
        """
#        LOG.debug('[Age] start: %s:%f'%( time.strftime('%H:%M', time.localtime(time.time())), time.time() % 60))
        delLsa = {'router': dict(),
                'network': dict(),
                'summary': dict(),
                'sum-asbr': dict(),
                'external': dict(),
                'nssa': dict(),
                'opaque-9': dict(),
                'opaque-10': dict(),
                'opaque-11': dict(),
        }
        delFlag = False
        for lsList in (self.ai.routerLsa,
                   self.ai.networkLsa,
                   self.ai.summaryLsa,
                   self.ai.summaryAsbrLsa,
                   self.ai.oi.asExternalLsa,
                   self.ai.opaque9Lsa,
                   self.ai.opaque10Lsa,
                   self.ai.oi.opaque11Lsa,
                   self.ai.oi.nssaLsa
            ):
            tobeRemoved = list()
            if len(lsList) == 0:
                continue
            else:
                lsdbLock.acquire()
                for lsa in lsList:
                    age = lsList[lsa]['H']['AGE']
                    doNotAge = lsList[lsa]['H']['DNA']
                    lsaTimestamp = util.strptime(datetimeLock, lsList[lsa]['TIMESTAMP'])
                    #print lsList[lsa]['TIMESTAMP']
                    nowAge = abs(lsaTimestamp - datetime.datetime.now()).seconds + age

                    #Remove aged LSA, rfc chap. 14
                    if doNotAge == 0 and nowAge >= MAXAGE:
                        for nrid in self.nbrList:
                            if len(self.nbrList[nrid].ls_rxmt) == 0 and\
                               (self.nbrList[nrid].state != NSM_STATE['NSM_Loading'] or
                                self.nbrList[nrid].state != NSM_STATE['NSM_Exchange']):
                                tobeRemoved.append(lsa)
                lsdbLock.release()
            tobeRemoved = list(set(tobeRemoved))

            if len(tobeRemoved) != 0:
                LOG.info("[LSA] %s LSA(s) aged for reaching MAXAGE." % len(tobeRemoved))
                delFlag = True
                lsdbLock.acquire()
                for rm in tobeRemoved:
                    #Maybe we received aged LSA in flood first, then the LSA will be deleted by flood. If this, pass it.
                    if rm not in lsList:
                        continue
                    ls, tp, aid, lsid, adv = self.ai.oi.generate_lsa_key(lsList[rm])
                    delLsa[self.ai.oi.lsa_tp_num2word(tp)][ls] = copy.deepcopy(lsList[rm])
                    del lsList[rm]
                lsdbLock.release()

        if delFlag:
            # send deleted lsa message to backend
            self.ai.oi.msgHandler.send_message('LS', 'DEL', delLsa, needRecord=True)

#        LOG.debug('[Age] stop: %s:%f'%( time.strftime('%H:%M', time.localtime(time.time())), time.time() % 60))


