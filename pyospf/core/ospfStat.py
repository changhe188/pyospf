# !/usr/bin/env python
# -*- coding:utf-8 -*-

import logging


LOG = logging.getLogger(__name__)


class OspfStat(object):
    """
    A global skeleton OSPF statistics
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(OspfStat, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self.total_received_packet_count = 0
        self.total_handled_packet_count = 0
        self.recv_hello_count = 0
        self.recv_dd_count = 0
        self.recv_lsr_count = 0
        self.recv_lsu_count = 0
        self.recv_lsack_count = 0
        self.total_send_packet_count = 0
        self.send_hello_count = 0
        self.send_dd_count = 0
        self.send_lsr_count = 0
        self.send_lsu_count = 0
        self.send_lsack_count = 0

    def get_stat_all(self):
        stat_all = {
            'total_recv_pkt': self.total_received_packet_count,
            'total_handle_pkt': self.total_handled_packet_count,
            'total_send_pkt': self.total_send_packet_count,
            'detail_recv': {
                'recv_hello': self.recv_hello_count,
                'recv_dd': self.recv_dd_count,
                'recv_lsr': self.recv_lsr_count,
                'recv_lsu': self.recv_lsu_count,
                'recv_lsack': self.recv_lsack_count,
            },
            'detail_send': {
                'send_hello': self.send_hello_count,
                'send_dd': self.send_dd_count,
                'send_lsr': self.send_lsr_count,
                'send_lsu': self.send_lsu_count,
                'send_lsack': self.send_lsack_count,
            }
        }
        return stat_all