#!/usr/bin/env python
# -*- coding:utf-8 -*-


import socket
import traceback


class Sock(object):

    def __init__(self, family, stype, proto=0, bufsize=1024 * 1024):
        self.family = family
        self.type = stype
        self.proto = proto
        self.buf = bufsize
        self._create()

    def _create(self):
        try:
            self.sock = socket.socket(self.family, self.type, self.proto)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception, e:
            print e

    def bind(self, ip='0.0.0.0', port=0):
        self.sock.bind((ip, port))

    def conn(self, ip, port=0, timeout=0):
        try:
            self.sock.connect((ip,port))
            if timeout is not 0:
                self.sock.settimeout(timeout)
            return True
        except Exception, e:
            if '111' in str(e):  # [Errno 111] Connection refused
                return False
            if '106' in str(e):  # [Errno 106] Transport endpoint is already connected
                return True
            return False

    def sendp(self, pack):
        try:
            self.sock.send(pack)
            return True
        except Exception, e:
            if '32' in str(e):  # [Errno 32] Broken pipe
                self.close()
                self._create()
            return False

    def recv(self):
        return self.sock.recvfrom(self.buf)

    def shutdown(self):
        self.sock.shutdown(socket.SHUT_RDWR)

    def close(self):
        self.sock.close()

    def set_blocking(self, flag):
        self.sock.setblocking(flag)

    def listen(self, num=1):
        self.sock.listen(num)

    def accept(self):
        return self.sock.accept()


class RawSock(Sock):

    def __init__(self, family, proto=0):
        self.proto = proto
        self.family = family
        Sock.__init__(self, self.family, socket.SOCK_RAW, self.proto)

