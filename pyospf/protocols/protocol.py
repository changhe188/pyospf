#!/usr/bin/env python
# -*- coding:utf-8 -*-


import logging

from pyospf.utils import util
from pyospf.core.basics.variable import *


LOG = logging.getLogger(__name__)


class OspfProtocol(object):

    version = 2
    helloInterval = 10  # default
    deadInterval = 4 * helloInterval
    area = 0
    rid = 0
    options = 0


    def set_ospf_header(self, v, a, r, o):
        self.version = v
        self.area = util.ip2int(a)
        self.rid = util.ip2int(r)
        self.options = self.calc_ospf_options(o)

    @staticmethod
    def lookup_lsa_list(tp, oi):
        """
        search the lsa should exist in which lsa list.
        """
        if tp == 1:  # router-lsa
            return oi.area.routerLsa
        elif tp == 2:
            return oi.area.networkLsa
        elif tp == 3:
            return oi.area.summaryLsa
        elif tp == 4:
            return oi.area.summaryAsbrLsa
        elif tp == 5:  # as-external-lsa
            return oi.asExternalLsa
        elif tp == 7:
            return oi.nssaLsa
        elif tp == 9:
            return oi.area.opaque9Lsa
        elif tp == 10:
            return oi.area.opaque10Lsa
        elif tp == 11:
            return oi.opaque11Lsa
        else:
            return None

    @staticmethod
    def lookup_lsa(lsa, lsaList):
        """
        :param lsa: is a tuple, like (type, id, adv)
        search in router-lsa, network-lsa, summary-lsa, as-external-lsa to find whether the lsa exists.
        :return entire lsa
        """
        if lsaList.has_key(lsa):
            return lsaList[lsa]
        else:
            return None

    @staticmethod
    def judge_new_lsa(l1, l2):
        """
        judge two lsas which one is newer.
        return None means two lsas equal.
        """
        if l1['LSSEQNO'] > l2['LSSEQNO']:
            return l1
        elif l1['LSSEQNO'] < l2['LSSEQNO']:
            return l2

        if l1['CKSUM'] > l2['CKSUM']:
            return l1
        elif l1['CKSUM'] < l2['CKSUM']:
            return l2

        if l1['AGE'] == MAXAGE:
            return l1
        elif l2['AGE'] == MAXAGE:
            return l2
        if abs(l1['AGE']-l2['AGE']) > MIN_AGE_DIFF:
            if l1['AGE'] < l2['AGE']:
                return l1
            else:
                return l2
        return None

    @staticmethod
    def calc_ospf_options(opt):
        """
        revert dictionary ospf options to int
        """
        if type(opt) != type({}) or len(opt) != 8:
            return None
        return opt['Q'] + opt['E'] * 2\
               + opt['MC'] * 4 + opt['NP'] * 8\
               + opt['L'] * 16 + opt['DC'] * 32\
               + opt['O'] * 64 + opt['DN'] * 128
