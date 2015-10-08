#!/usr/bin/env python
# -*- coding:utf-8 -*-

__author__ = 'changhe'

import struct, socket, string, sys, datetime, ipaddr, re


def find_num_in_string(string):
    reg = re.compile('r[^0-9]*(\d*)[^0-9]*')
    return reg.findall(string)


def isSet(bit):
    if bit > 0:
        return 1
    else:
        return 0


def find_key(dict, value):
    res = []
    for v in dict.items():
        if v[1] == value:
            res.append(v[0])
    return res


def ip2int(ip):
    return ipaddr.IPv4Address(ip)._ip


def int2ip(i):
    if isinstance(i, str):
        i = int(i)
    return socket.inet_ntoa(struct.pack("!I", i))


def intpack(id):
    return struct.pack('!I', id)


def error(message):
    sys.stderr.write(message)
    sys.stderr.flush()


def mask2plen(mask):

    rv = 32
    while mask % 2 == 0:
        rv = rv - 1
        mask = mask >> 1

    return rv


def plen2mask(plen):

    return pow(2L, 32) - pow(2L, 32-plen)


def pfx2id(pfx, plen=None):

    if plen == None:
        plen = pfx[1]
        pfx  = pfx[0]

    mask = plen2mask(plen)
    p    = 0
    for i in range(len(pfx)):
        p = p << 8
        p = p | ord(pfx[i])
    p = p << (8 * (4-len(pfx)))
    p = p & mask

    return p


def addrmask2str(addr, mask):

    plen = mask2plen(mask)
    id   = addr & mask
    return "%s/%d" % (id2str(id), plen)


def pfx2str(pfx, plen=None):

    if plen == None:
        plen = int(pfx[1])
        pfx  = pfx[0]

    mask = plen2mask(plen)
    p = 0
    for i in range(len(pfx)):
        p = p << 8
        p = p | ord(pfx[i])
    p = p << (8 * (4-len(pfx)))
    p = p & mask

    return "%s/%d" % (id2str(p), plen)


def rpfx2str(pfxtup):

    plen, pfx = pfxtup

    p = 0
    for i in range(len(pfx)):
        p = p << 8
        p = p | ord(pfx[i])
    p = p << (8 * (4-len(pfx)))

    return "%s/%d" % (id2str(p), plen)


def id2pfx(id):

    a = int( ((id & 0xff000000L) >> 24) & 0xff)
    b = int( ((id & 0x00ff0000)  >> 16) & 0xff)
    c = int( ((id & 0x0000ff00)  >>  8) & 0xff)
    d = int( ((id & 0x000000ff))        & 0xff)

    return struct.pack('4B', a, b, c, d)


def id2str(id):

    return "%d.%d.%d.%d" %\
           (int( ((id & 0xff000000L) >> 24) & 0xff),
            int( ((id & 0x00ff0000)  >> 16) & 0xff),
            int( ((id & 0x0000ff00)  >>  8) & 0xff),
            int( (id  & 0x000000ff)         & 0xff) )


def str2id(str):

    quads = string.split(str, '.')
    ret   = (string.atol(quads[0]) << 24) + (string.atol(quads[1]) << 16) +\
            (string.atol(quads[2]) <<  8) + (string.atol(quads[3]) <<  0)
    return ret


def str2pfx(strng):

    pfx, plen = string.split(strng, '/')
    plen = string.atoi(plen)

    pfx = string.split(pfx, '.')
    p   = ''
    for e in pfx:
        p = struct.pack('%dsB' % len(p), p, string.atoi(e))
    pfx = p

    return (pfx, plen)


def isid2id(str):

    str = string.join(string.split(str2hex(str), '.'), '')
    str = "%s.%s.%s.%s" % (str[0:3], str[3:6], str[6:9], str[9:12])

    return str2id(str)

def str2hex(str):

    if str == None or str == "":
        return ""

    ret = map(lambda x: '%0.2x' % x, map(ord, str))
    ret = string.join(ret, '.')

    return ret


def prthex(pfx, str):

    if str == None or str == "":
        return ""

    ret = ""
    for i in range(0, len(str), 16):
        ret = ret + '\n' + pfx + '0x' + str2hex(str[i:i+16])
    return ret


def str2mac(str):

    bytes = string.split(str, '.')
    if len(bytes) != 6:
        return

    bytes = map(lambda x: string.atoi(x, 16), bytes)
    return struct.pack("BBB BBB",
        bytes[0], bytes[1], bytes[2],
        bytes[3], bytes[4], bytes[5])


def str2bin(str):

    if str == None or str == "":
        return ""

    ret = ""
    for i in range(len(str)):
        s = ""
        n = ord(str[i])
        for j in range(7, -1, -1):
            b = n / (2**j)
            n = n % (2**j)
            s = s + `b`
        ret = ret + ("%s." % s)

    return ret


def prtbin(pfx, str):

    if str == None or str == "":
        return ""

    ret = ""
    for i in range(0, len(str), 8):
        ret = ret + '\n' + pfx + str2bin(str[i:i+8])
    return ret


def int2bin(int):

    # XXX this breaks for negative numbers since >> is arithmetic (?)
    # -- ie. -1 >> 1 == -1...

    if int == 0: return '00000000'

    ret = "" ; bit = 0
    while int != 0:
        if bit % 8 == 0: ret = '.' + ret
        ret = `int%2` + ret
        int = int >> 1
        bit += 1

    if bit % 8 != 0: ret = (8 - bit%8)*"0" + ret
    return ret[:-1]


def int2hex(i):

    if i == 0:
        return "00"
    else:
        ret = ""

    while i != 0:
        ret = "%0.2x." % (i&0xff) + ret
        i = i >> 8

    return ret[:-1]


def ospf_lsa_checksum(lsa):
    """
    Fletcher checksum for OSPF LSAs.
    If passed check, return 0
    """
    CHKSUM_OFFSET = 16
    if len(lsa) < CHKSUM_OFFSET:
        return None
    c0 = c1 = 0
    for char in lsa[2:]:  #  leave out age
        c0 += ord(char)
        c1 += c0
    c0 %= 255
    c1 %= 255

    return (c1 << 8) + c0


def strptime(lock, time):
    """
    Translate string time to datetime object.
    """
    with lock:
        try:
            r = datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S.%f')
        except Exception, e:
            #TODO: sometimes exception here, do not find reason
            r = datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
    return r


def current_time():
    return str(datetime.datetime.now())


def hex2byte(hexStr):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i+2], 16)))

    return ''.join(bytes)