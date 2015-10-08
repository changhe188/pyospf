#!/usr/bin/env python
# -*- coding:utf-8 -*-

from interfaceStateMachine import ISM


class OspfArea(object):

    transit_capability = False            # unused
    external_routing_capability = False   # unused
    stub_def_cost = 0                     # unused

    def __init__(self, oi):

        self.router_lsa = dict()
        self.network_lsa = dict()
        self.summary_lsa = dict()
        self.summary_asbr_lsa = dict()
        self.opaque9_lsa = dict()
        self.opaque10_lsa = dict()

        self.oi = oi
        self.area_id = oi.config['area']

        #one probe has only one interface connect to one area, so there is only one ism in area.
        self.interface = ISM(self)


