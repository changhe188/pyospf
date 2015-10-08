# !/usr/bin/env python
# -*- coding:utf-8 -*-

import logging
import threading


LOG = logging.getLogger(__name__)


class OspfLsdb(object):
    """
    A global skeleton OSPF LSDB
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(OspfLsdb, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, oi):
        self.lsdb = {
            'router': oi.area.router_lsa,
            'network': oi.area.network_lsa,
            'summary': oi.area.summary_lsa,
            'sum-asbr': oi.area.summary_asbr_lsa,
            'external': oi.as_external_lsa,
            'nssa': oi.nssa_lsa,
            'opaque-9': oi.area.opaque9_lsa,
            'opaque-10': oi.area.opaque10_lsa,
            'opaque-11': oi.opaque11_lsa
        }

        self.lsdb_lock = threading.RLock()

    def empty_lsdb(self):
        self.lsdb_lock.acquire()
        for lsa_type in self.lsdb:
            self.lsdb[lsa_type].clear()
        self.lsdb_lock.release()
        LOG.info('[LSDB] Delete all LSAs in LSDB.')

    def lookup_lsa_list(self, tp):
        """
        search the lsa should exist in which lsa list.
        """
        if tp == 1:
            return self.lsdb['router']
        elif tp == 2:
            return self.lsdb['network']
        elif tp == 3:
            return self.lsdb['summary']
        elif tp == 4:
            return self.lsdb['sum-asbr']
        elif tp == 5:
            return self.lsdb['external']
        elif tp == 7:
            return self.lsdb['nssa']
        elif tp == 9:
            return self.lsdb['opaque-9']
        elif tp == 10:
            return self.lsdb['opaque-10']
        elif tp == 11:
            return self.lsdb['opaque-11']
        else:
            return None

    @staticmethod
    def convert_lsa_type_name(tp):
        """
        Translate LSA type number to name word.
        """
        name = {1: 'router', 2: 'network', 3: 'summary', 4: 'sum-asbr', 5: 'external',
                7: 'nssa', 9: 'opaque-9', 10: 'opaque-10', 11: 'opaque-11'}
        if int(tp) in name:
            return name[tp]
        else:
            return None
