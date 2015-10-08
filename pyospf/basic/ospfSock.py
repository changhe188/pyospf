#!/usr/bin/env python
# -*- coding:utf-8 -*-


import struct
import logging
import socket

from dpkt.ip import *

from pyospf.utils.sock import RawSock
from pyospf.basic.constant import *


LOG = logging.getLogger(__name__)


class OspfSock(RawSock):

    #Two multicast address used by ospf, but probe doesn't need to listen to 224.0.0.6
    ospf_addr = [ALL_SPF_ROUTER, ALL_D_ROUTER]

    def __init__(self):

        RawSock.__init__(self, socket.AF_INET, IP_PROTO_OSPF)

    def add_ospf_multicast_group(self, intf_ip=socket.INADDR_ANY):
        LOG.debug('[Sock] Add to multicast group.')

        try:
            #IP_MULTICAST_LOOP makes socket do not receive the packet sent by itself, but it didn't work.
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            for addr in self.ospf_addr:
                #intf_ip refers to the local interface ip.
                if intf_ip == socket.INADDR_ANY:
                    mcast = struct.pack('4sl', socket.inet_aton(addr), intf_ip)
                else:
                    mcast = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(intf_ip))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mcast)
        except Exception, e:
            print e

    def bind_ospf_multicast_group(self, interface):
        self.sock.setsockopt(socket.SOL_SOCKET, 25, interface)  # 25 stands for socket.SO_BINDTODEVICE

    def drop_ospf_multicast_group(self, intf_ip=socket.INADDR_ANY):
        LOG.debug('[Sock] Drop multicast group.')

        try:
            for addr in self.ospf_addr:
                if intf_ip == socket.INADDR_ANY:
                    mcast = struct.pack('4sl', socket.inet_aton(addr), intf_ip)
                else:
                    mcast = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(intf_ip))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mcast)
        except Exception, e:
            print e



