#!/usr/bin/env python
# -*- coding:utf-8 -*-


import datetime
import copy
import logging

from pyospf.protocols.hello import HelloProtocol
from pyospf.basic.constant import *
from pyospf.utils.timer import Timer
from pyospf.utils.util import *


LOG = logging.getLogger(__name__)


class ISM(object):

    def __init__(self, ai):
        self.state = ISM_STATE['ISM_Down']

        self.inf_trans_delay = 1  # TODO: how to set?
        self.prior = 0          # set probe priority 0 permanently
        self.drip = 0
        self.bdrip = 0
        self.neighbor = list()      # save all neighbors rid
        self.nbr_list = dict()       # save all neighbors' state(nsm), format: {nrid: nsm}
        self.output_cost = 0     # TODO: how to set?

        self.au_type = 0         # TODO: Auth not implement
        self.au_key = None       # TODO: Auth not implement

        self._hello_timer = None
        self._elect_timer = None
        self._lsa_age_timer = None

        self.lsa_age_step = 1     # check LSA age interval

        self.ai = ai

        self.version = 2
        self.rid = ai.oi.rid
        self.area_id = ai.area_id
        self.hello_interval = ai.oi.config['hello_interval']
        self.dead_interval = 4 * self.hello_interval
        self.ip_intf_addr = ai.oi.config['ip']
        self.ip_intf_mask = ai.oi.config['mask']
        self.link_type = ai.oi.config['link_type']
        self.options = ai.oi.config['options']
        self.rxmt_interval = ai.oi.config['rxmt_interval']
        self.mtu = ai.oi.config['mtu']

        # self.multiAreaCap = False
        # #rfc5185 multi-area adj support
        # if ai.oi.config.has_key('multiArea'):
        #     self.multiAreaCap = True
        #     self.multiArea = ai.oi.config['multiArea']

        self.hp = HelloProtocol(self)
        self.ism = dict()

        #register all ism events
        for ismevent in ISM_EVENT.keys():
            if ismevent == 'ISM_InterfaceUp':
                self.ism[ismevent] = self._interface_up
            elif ismevent == 'ISM_InterfaceDown':
                self.ism[ismevent] = self._down
            elif ismevent == 'ISM_BackupSeen':
                self.ism[ismevent] = self._dr_other
            elif ismevent == 'ISM_WaitTimer':
                self.ism[ismevent] = self._dr_other
            elif ismevent == 'ISM_NeighborChange':
                self.ism[ismevent] = self._nbr_change
            else:
                continue

        self.nbrDownFlag = False    # Whether neighbor down happened

    def fire(self, event):
        self.ism[event]()

    def _down(self):
        """
        To interface down state
        """
        if not self._hello_timer is None:
            self._hello_timer.stop()
            self._hello_timer = None
        if not self._lsa_age_timer is None:
            self._lsa_age_timer.stop()
            self._lsa_age_timer = None
        if not self._elect_timer is None:
            self._elect_timer.stop()
            self._elect_timer = None
        self.change_ism_state('ISM_Down')
        self.drip = 0
        self.bdrip = 0
        self.neighbor = list()
        self.nbr_list = dict()

    def _interface_up(self):
        """
        Handler for interface up event
        """
        #point to point link, go to point_to_point state directly
        if self.link_type == 'Point-to-Point':
            self._point_to_point()
        #broadcast link, go to dr other state
        elif self.link_type == 'Broadcast':
            self._waiting()
        else:
            LOG.error('[ISM] Wrong Link Type.')
            return

    def _waiting(self):
        self.change_ism_state('ISM_Waiting')
        self._begin_hello()
        self._hello_timer = Timer(self.hello_interval, self._begin_hello)
        self._hello_timer.start()
        self._elect_timer = Timer(self.dead_interval, self._elect_dr, once=True)
        self._elect_timer.start()

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
        self._hello_timer = Timer(self.hello_interval, self._begin_hello)
        self._hello_timer.start()
        #start a timer to check all lsa age per lsaAgeStep second
        #TODO: this implementation should be checked.
        if self._lsa_age_timer is None:
            self._lsa_age_timer = Timer(self.lsa_age_step, self._lsa_age)
            self._lsa_age_timer.start()
            LOG.debug('[ISM] Start LSA age timer.')

    def _begin_hello(self):
        #start Hello Protocol
        self.hp.set_conf(
            self.version,
            self.hello_interval,
            self.dead_interval,
            self.rid,
            self.area_id,
            self.ip_intf_mask,
            self.options,
            self.link_type,
            self.drip,
            self.bdrip
        )
        self.hp.send_hello(self.hp.gen_hello())

    def _dr_other(self):
        """
        send hello in broadcast or nbma, not be dr
        """
        self.change_ism_state('ISM_DROther')
        if not self._elect_timer.is_stop():
            self._elect_timer.stop()
        #start a timer to check all lsa age per lsaAgeStep second
        #TODO: this implementation should be checked.
        if self._lsa_age_timer is None:
            self._lsa_age_timer = Timer(self.lsa_age_step, self._lsa_age)
            self._lsa_age_timer.start()
            LOG.debug('[ISM] Start LSA age timer.')

    def _nbr_change(self):
        #Remove NSM which state is down
        tobe_removed = []
        for nrid in self.nbr_list:
            if self.nbr_list[nrid].state == NSM_STATE['NSM_Down']:
                tobe_removed.append(nrid)

        for rm in tobe_removed:
            if self.nbr_list[rm].src == self.drip:
                self.drip = 0
            if self.nbr_list[rm].src == self.bdrip:
                self.bdrip = 0
            del self.nbr_list[rm]
            self.neighbor.remove(rm)
            LOG.info('[ISM] Neighbor %s is deleted.' % int2ip(rm))

        if self.link_type == 'Broadcast':
            if not self._elect_timer.is_stop():
                self._elect_timer.stop()
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
        #TODO: unimplemented
        LOG.debug('[ISM] Election Finished.')
        if self.state == ISM_STATE['ISM_Waiting']:
            #Receive some cross-thread flag change, and then fire the event
            LOG.info('[ISM] Event: ISM_WaitTimer.')
            self.fire('ISM_WaitTimer')
        else:
            self._dr_other()

    def change_ism_state(self, newstate):
        LOG.info("[ISM] Change state to %s." % newstate)
        self.state = ISM_STATE[newstate]

    def _lsa_age(self):
        """
        Check all LSA age, and when LSA's age is MAXAGE, call aged handler
        """
        for lslist in self.ai.oi.lsdb.lsdb.values():
            tobe_removed = list()
            if len(lslist) == 0:
                continue
            else:
                self.ai.oi.lsdb.lsdb_lock.acquire()
                for lsa in lslist:
                    age = lslist[lsa]['H']['AGE']
                    dna = lslist[lsa]['H']['DNA']
                    lsa_ts = strptime(datetimeLock, lslist[lsa]['TIMESTAMP'])
                    now_age = abs(lsa_ts - datetime.datetime.now()).seconds + age

                    #Remove aged LSA, rfc chap. 14
                    if dna == 0 and now_age >= MAXAGE:
                        for nrid in self.nbr_list:
                            if len(self.nbr_list[nrid].ls_rxmt) == 0 and\
                               (self.nbr_list[nrid].state != NSM_STATE['NSM_Loading'] or
                                self.nbr_list[nrid].state != NSM_STATE['NSM_Exchange']):
                                tobe_removed.append(lsa)
                self.ai.oi.lsdb.lsdb_lock.release()
            tobe_removed = list(set(tobe_removed))

            if len(tobe_removed) != 0:
                LOG.info("[LSA] %s LSA(s) aged for reaching MAXAGE." % len(tobe_removed))
                self.ai.oi.lsdb.lsdb_lock.acquire()
                for rm in tobe_removed:
                    #Maybe we received aged LSA in flood, then the LSA will be deleted by flood. If this, pass it.
                    if rm not in lslist:
                        continue
                    del lslist[rm]
                self.ai.oi.lsdb.lsdb_lock.release()


