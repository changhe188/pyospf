#!/usr/bin/env python
# -*- coding:utf-8 -*-


import logging

from pyospf.utils import util
from pyospf.basic.constant import *


LOG = logging.getLogger(__name__)


class OspfProtocol(object):

    version = 2
    hello_interval = 10  # default
    dead_interval = 4 * hello_interval
    area = 0
    rid = 0
    options = 0

    def set_ospf_header(self, v, a, r, o):
        self.version = v
        self.area = util.ip2int(a)
        self.rid = util.ip2int(r)
        self.options = self.convert_options_to_int(o)

    @staticmethod
    def lookup_lsa(lsa, lsa_list):
        """
        :param lsa: is a tuple, like (type, id, adv)
        search in router-lsa, network-lsa, summary-lsa, as-external-lsa to find whether the lsa exists.
        :return entire lsa
        """
        if lsa in lsa_list:
            return lsa_list[lsa]
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
    def generate_lsa_key(lsa):
        """
        Generate the key of the LSA.
        :param lsa:
        :return:
        """
        tp, lsid, adv, aid = lsa['H']['T'], lsa['H']['LSID'], lsa['H']['ADVRTR'], lsa['AREA']
        if int(lsa['H']['T']) == 5:
            ls = str((tp, lsid, adv))
        else:
            ls = str((tp, aid, lsid, adv))
        return ls, tp, aid, lsid, adv

    @staticmethod
    def convert_options_to_int(opt):
        """
        convert dictionary ospf options to int
        """
        if (not isinstance(opt, dict)) or len(opt) != 8:
            return None
        return opt['Q'] + opt['E'] * 2\
               + opt['MC'] * 4 + opt['NP'] * 8\
               + opt['L'] * 16 + opt['DC'] * 32\
               + opt['O'] * 64 + opt['DN'] * 128

    @staticmethod
    def parse_options_config(opt):
        """
        Convert the config parameter options to dictionary
        :param opt: options config string
        :return: options in dictionary type
        """
        opt_dict = {'Q': 0, 'E': 0, 'MC': 0, 'NP': 0, 'L': 0, 'DC': 0, 'O': 0, 'DN': 0}
        list_options = opt.split(',')
        for bit in opt_dict.keys():
            if bit in list_options:
                opt_dict[bit] = 1
        return opt_dict
