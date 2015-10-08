#!/usr/bin/env python
# -*- coding:utf-8 -*-


##     PyRT: Python Routeing Toolkit

##     OSPF module: provides the OSPF listener and OSPF PDU parsers

##     Copyright (C) 2010 Richard Mortier <mort@cantab.net>

##     This program is free software; you can redistribute it and/or
##     modify it under the terms of the GNU General Public License as
##     published by the Free Software Foundation; either version 2 of the
##     License, or (at your option) any later version.

##     This program is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##     General Public License for more details.

##     You should have received a copy of the GNU General Public License
##     along with this program; if not, write to the Free Software
##     Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
##     02111-1307 USA

# RFC 1584 -- MOSPF
# RFC 2328 -- OSPF v2
# RFC 2370 -- Opaque LSAs (updated by RFC 3670)
#   [ This is such a mess compared with IS-IS!  Opaque LSAs have a
#   different LSA header format due to the need to encode an Opaque
#   LSA type ]
# RFC 2676 -- QoS routing mechanisms
# RFC 3101 -- Not-so-stubby-area (NSSA) option
# RFC 3137 -- Stub routers (where metric == 0xffffff > LSInfinity, 0xffff)
# RFC 3623 -- Graceful restart
# RFC 3630 -- Traffic engineering extensions

## LSUPD/LSA notes:

# router id:
#    the IP address of the router that generated the packet
# advrtr:
#    the IP address of the advertising router
# src:
#    the IP address of the interface from which the LSUPD came

# link state id (lsid):
#    identifier for this link (interface) dependent on type of LSA:
#      1 (router)       ID of router generating LSA
#      2 (network)      IP address of DR for LAN
#      3 (summary IP)   IP address of link reported as dst
#      4 (summary ASBR) IP address of reachable ASBR
#      5 (external AS)  IP address of link reported as dst

# link id:
#    what is connected to this router by this link, dependent on type
#      1 (p2p)          ID of neighbour router
#      2 (transit)      IP address of DR for LAN
#      3 (stub)         IP address of LAN (no DR since a stub network)
#      4 (virtual)      ID of neighbour router
# link data:
#    subnet mask if lsid==3; else IP address of the router that
#    generated the LSA on the advertised link (~= advrtr?)

# summary LSA:
#    created by ASBR and flooded into area; type 3 report cost to
#    prefix outside area, type 4 report cost to ASBR

import traceback
import logging
import dpkt

from pyospf.utils.util import *

# from sender.event import Event

LOG = logging.getLogger(__name__)
#-------------------------------------------------------------------------------

INDENT          = "    "
VERSION         = "2.9"

RECV_BUF_SZ      = 8192
OSPF_LISTEN_PORT = 89
LS_INFINITY      = 0xffff
LS_STUB_RTR      = 0xffffff

IP_HDR     = "> BBH HH BBH LL"
IP_HDR_LEN = struct.calcsize(IP_HDR)

OSPF_HDR     = "> BBH L L HH L L"
OSPF_HDR_LEN = struct.calcsize(OSPF_HDR)

OSPF_HELLO     = "> L HBB L L L"
OSPF_HELLO_LEN = struct.calcsize(OSPF_HELLO)

OSPF_DESC     = "> HBB L"
OSPF_DESC_LEN = struct.calcsize(OSPF_DESC)

OSPF_LSREQ     = "> L L L"
OSPF_LSREQ_LEN = struct.calcsize(OSPF_LSREQ)

OSPF_LSUPD     = "> L"
OSPF_LSUPD_LEN = struct.calcsize(OSPF_LSUPD)

OSPF_LSAHDR     = "> HBB L L L HH"
OSPF_LSAHDR_LEN = struct.calcsize(OSPF_LSAHDR)

OSPF_LSARTR     = "> BBH"
OSPF_LSARTR_LEN = struct.calcsize(OSPF_LSARTR)

OSPF_LSANET     = "> L"
OSPF_LSANET_LEN = struct.calcsize(OSPF_LSANET)

OSPF_LINK     = "> L L BBH"
OSPF_LINK_LEN = struct.calcsize(OSPF_LINK)

OSPF_METRIC     = "> BBH"
OSPF_METRIC_LEN = struct.calcsize(OSPF_METRIC)

OSPF_LSASUMMARY     = "> L"
OSPF_LSASUMMARY_LEN = struct.calcsize(OSPF_LSASUMMARY)

OSPF_LSAEXT     = "> L"
OSPF_LSAEXT_LEN = struct.calcsize(OSPF_LSAEXT)

OSPF_LSAEXT_METRIC     = "> BBH L L"
OSPF_LSAEXT_METRIC_LEN = struct.calcsize(OSPF_LSAEXT_METRIC)

OSPF_OPAQUE_TL     = "> HH"
OSPF_OPAQUE_TL_LEN = struct.calcsize(OSPF_OPAQUE_TL)

################################################################################

DLIST = []

ADDRS = { str2id("224.0.0.5"): "AllSPFRouters",
          str2id("224.0.0.6"): "AllDRouters",
          }
DLIST += [ADDRS]

AFI_TYPES = { 1L: "IP",
              2L: "IP6",
              }
DLIST += [AFI_TYPES]

MSG_TYPES = { 1L: "HELLO",
              2L: "DBDESC",
              3L: "LSREQ",
              4L: "LSUPD",
              5L: "LSACK",
              }
DLIST += [MSG_TYPES]

AU_TYPES = { 0L: "NULL",
             1L: "PASSWD",
             2L: "CRYPTO",
             }
DLIST += [AU_TYPES]

LSA_TYPES = { 1L: "ROUTER",             # links between routers in the area
              2L: "NETWORK",            # links between "networks" in the area
              3L: "SUMMARY (IP)",       # networks rechable outside area; gen. by ASBR
              4L: "SUMMARY (ASBR)",     # ASBRs reachable outside area; gen. by (local) ASBR
              5L: "EXTERNAL AS",        # prefixes reachable outside the AS; gen. by (local) ASBR

              6L: "MOSPF",
              7L: "NSSA",

              9L: "OPAQUE LINK LOCAL",
              10L: "OPAQUE AREA LOCAL",
              11L: "OPAQUE AS LOCAL",
              }
DLIST += [LSA_TYPES]

OPAQUE_TYPES = { 1L: "TRAFFIC ENGINEERING",
                 3L: "GRACEFUL RESTART",
                 }
DLIST += [OPAQUE_TYPES]

TE_TLV_TS = { 1L: "ROUTER ADDRESS",
              2L: "LINK",
              }
DLIST += [TE_TLV_TS]

TE_TLV_LS = { 1L: 4,
              2L: 0, ## variable
}

TE_LINK_SUBTYPES = { 1L: "TYPE",
                     2L: "ID",
                     3L: "LOCAL IF",
                     4L: "REMOTE IF",
                     5L: "TE METRIC",
                     6L: "MAX BW",
                     7L: "MAX RSVBL BW",
                     8L: "UNRSVD BW",
                     9L: "ADMIN GROUP",
                     }
DLIST += [TE_LINK_SUBTYPES]

TE_LINK_SUBTYPE_LS = { 1L: 1,
                       2L: 4,
                       3L: 4,
                       4L: 4,
                       5L: 4,
                       6L: 4,
                       7L: 4,
                       8L: 32,
                       9L: 4,
                       }

GRACE_TLV_TS = { 1L: "PERIOD",
                 2L: "REASON",
                 3L: "IP ADDR",
                 }
DLIST += [GRACE_TLV_TS]

GRACE_REASONS = { 0L: "UNKNOWN",
                  1L: "SW RESTART",
                  2L: "SW RELOAD/UPGRADE",
                  3L: "SWITCH REDUNDANT RCP",
                  }
DLIST += [GRACE_REASONS]

GRACE_TLV_LS = { 1L: 4,
                 2L: 1,
                 3L: 4,
                 }

RTR_LINK_TYPE = { 1L: "P2P",
                  2L: "TRANSIT",
                  3L: "STUB",
                  4L: "VIRTUAL",
                  }

DLIST += [RTR_LINK_TYPE]

for d in DLIST:
    for k in d.keys():
        d[ d[k] ] = k

################################################################################

def parseIpHdr(msg, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, msg[:IP_HDR_LEN])


    (verhlen, tos, iplen, ipid, frag, ttl, proto, cksum, src, dst) =\
    struct.unpack(IP_HDR, msg)

    #check check sum
    # if dpkt.in_cksum(msg):
    #     LOG.error('[ERROR] IP header checksum error.')
    #     return None

    ver  = (verhlen & 0xf0) >> 4
    hlen = (verhlen & 0x0f) * 4

    if verbose > 0:
        print level*INDENT +\
              "IP (len=%d)" % len(msg)
        print (level+1)*INDENT +\
              "ver:%s, hlen:%s, tos:%s, len:%s, id:%s, frag:%s, ttl:%s, prot:%s, cksm:%x" %\
              (ver, hlen, int2bin(tos), iplen, ipid, frag, ttl, proto, cksum)
        print (level+1)*INDENT +\
              "src:%s, dst:%s" % (id2str(src), id2str(dst))



    return { "VER"   : ver,
             "HLEN"  : hlen,
             "TOS"   : tos,
             "IPLEN" : iplen,
             "IPID"  : ipid,
             "FRAG"  : frag,
             "TTL"   : ttl,
             "PROTO" : proto,
             "CKSUM" : cksum,
             "SRC"   : src,
             "DST"   : dst
    }

def parseOspfHdr(msg, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, msg[:OSPF_HDR_LEN])
    (ver, typ, len, rid, aid, cksum, autype, auth1, auth2) = struct.unpack(OSPF_HDR, msg)
#    if True:
    if verbose > 0:
        print level*INDENT +\
              "OSPF: ver:%s, type:%s, len:%s, rtr id:%s, area id:%s, cksum:%x, autype:%s" %\
              (ver, MSG_TYPES[typ], len, id2str(rid), id2str(aid), cksum, AU_TYPES[autype],)

    return { "VER"    : ver,
             "TYPE"   : typ,
             "LEN"    : len,
             "RID"    : rid,
             "AID"    : aid,
             "CKSUM"  : cksum,
             "AUTYPE" : autype,
             "AUTH1"  : auth1,
             "AUTH2"  : auth2,
             }

def parseOspfOpts(opts, verbose=1, level=0):

    if verbose > 1: print level*INDENT + int2bin(opts)

    qbit  = (opts & 0x01) ## RFC 2676; reclaim original "T"-bit for TOS routing cap.
    ebit  = (opts & 0x02) >> 1
    mcbit = (opts & 0x04) >> 2
    npbit = (opts & 0x08) >> 3
    lbit = (opts & 0x10) >> 4
    dcbit = (opts & 0x20) >> 5
    obit  = (opts & 0x40) >> 6
    dnbit = (opts & 0x80) >> 7

    if verbose > 0:
        print level*INDENT + "options: %s %s %s %s %s %s %s %s" %(
            qbit*"Q", ebit*"E", mcbit*"MC", npbit*"NP", lbit*"EA", dcbit*"DC", obit*"O", dnbit*'DN')

    return { "Q"  : qbit,
             "E"  : ebit,
             "MC" : mcbit,
             "NP" : npbit,
             "L" : lbit,
             "DC" : dcbit,
             "O"  : obit,
             "DN" : dnbit
             }

def parseOspfLsaHdr(hdr, verbose=1, level=0):

#    if len(hdr) != OSPF_LSAHDR_LEN:
#        print '------', len(hdr)
    (age, opts, typ, lsid, advrtr, lsseqno, cksum, length) = struct.unpack(OSPF_LSAHDR, hdr)

    if verbose > 0:
        print level*INDENT +\
              "age:%s, type:%s, lsid:%s, advrtr:%s, lsseqno:%s, cksum:%x, len:%s" %(
                  age, LSA_TYPES[typ], id2str(lsid), id2str(advrtr), lsseqno, cksum, length)

    #Parse the first bit to check whether set DNA bit
    doNotAge = age >> 15
    if doNotAge == 1:
        age = age & 0x7FFF

    opts = parseOspfOpts(opts, verbose, level)

    return { "DNA"     : doNotAge,
             "AGE"     : age,
             "OPTS"    : opts,
             "T"       : typ,
             "LSID"    : lsid,
             "ADVRTR"  : advrtr,
             "LSSEQNO" : lsseqno,
             "CKSUM"   : cksum,
             "L"       : length,
             }

def parseOspfLsaRtr(lsa, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, lsa[:OSPF_LSARTR_LEN])
    (veb, _, nlinks, ) = struct.unpack(OSPF_LSARTR, lsa[:OSPF_LSARTR_LEN])
    b = (veb & 0x01)
    e = (veb & 0x02) >> 1
    v = (veb & 0x04) >> 2
    if verbose > 0:
        print level*INDENT + "nlinks:%s, rtr desc: %s %s %s" %(
            nlinks, v*"VIRTUAL", e*"EXTERNAL", b*"BORDER")

    lsa = lsa[OSPF_LSARTR_LEN:] ; i = 0 ; links = {}
    while i < nlinks:
        i += 1

        if verbose > 1: print prtbin((level+1)*INDENT, lsa[:OSPF_LINK_LEN])
        (lid, ldata, ltype, ntos, metric) = struct.unpack(OSPF_LINK, lsa[:OSPF_LINK_LEN])
        if verbose > 0:
            print (level+1)*INDENT +\
                  "%s: link id:%s, link data:%s, link type:%s, ntos:%s, metric:%s" %(
                      i, id2str(lid), id2str(ldata), RTR_LINK_TYPE[ltype], ntos, metric)

        lsa = lsa[OSPF_LINK_LEN:] ; j = 0 ; metrics = { 0: metric, }
        while j < ntos:
            j += 1

            if verbose > 1: print prtbin((level+2)*INDENT, lsa[:OSPF_METRIC_LEN])
            (tos, _, metric) = struct.unpack(OSPF_METRIC, lsa[:OSPF_METRIC_LEN])
            if verbose > 0:
                print (level+2)*INDENT +\
                      "%s: tos:%s, metric:%s" % (j, int2bin(tos), metric)
            metrics[tos] = metric
            lsa = lsa[OSPF_METRIC_LEN:]

        links[i] = { "ID"      : lid,
                     "DATA"    : ldata,
                     "T"       : ltype,
                     "NTOS"    : ntos,
                     "METRICS" : metrics,
                     }

    return { "VIRTUAL"  : v,
             "EXTERNAL" : e,
             "BORDER"   : b,
             "NLINKS"   : nlinks,
             "LINKS"    : links,
             }

def parseOspfLsaNet(lsa, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, lsa[:OSPF_LSANET_LEN])
    (mask, ) = struct.unpack(OSPF_LSANET, lsa[:OSPF_LSANET_LEN])
    if verbose > 0: print level*INDENT + "mask:%s" % (id2str(mask), )

    lsa = lsa[OSPF_LSANET_LEN:] ; cnt = 0 ; rtrs = []
    while len(lsa) > 0:
        cnt += 1

        if verbose > 1: print prtbin((level+1)*INDENT, lsa[:OSPF_LSANET_LEN])
        (rtr,) = struct.unpack(OSPF_LSANET, lsa[:OSPF_LSANET_LEN])
        if verbose > 0:
            print (level+1)*INDENT + "%s: attached rtr:%s" % (cnt, id2str(rtr))

        rtrs.append(rtr)
        lsa = lsa[OSPF_LSANET_LEN:]

    return { "MASK" : mask,
             "RTRS" : rtrs
    }

def parseOspfLsaSummary(lsa, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, lsa[:OSPF_LSASUMMARY_LEN])
    (mask, ) = struct.unpack(OSPF_LSASUMMARY, lsa[:OSPF_LSASUMMARY_LEN])
    if verbose > 0:
        print level*INDENT + "mask:%s" % (id2str(mask), )

    lsa = lsa[OSPF_LSASUMMARY_LEN:] ; cnt = 0 ; metrics = {}
    while len(lsa) > 0:
        cnt += 1

        if verbose > 1: print prtbin((level+1)*INDENT, lsa[:OSPF_METRIC_LEN])
        (tos, stub, metric) = struct.unpack(OSPF_METRIC, lsa[:OSPF_METRIC_LEN])

        ## RFC 3137 "Stub routers": if (stub,metric) == (0xff, 0xffff)
        ## then this is a stub router and it is attempting to
        ## discourage other routers from using it to transit traffic,
        ## ie. forward traffic to any networks others than those
        ## connected directly

        metric = ((stub<<16) | metric)
        if verbose > 0:
            if metric == LS_STUB_RTR: mstr = "metric:STUB_ROUTER"
            elif metric > LS_INFINITY: mstr = "*** metric:%s > LS_INFINITY! ***" % metric
            elif metric == LS_INFINITY: mstr = "metric:LS_INFINITY"
            else: mstr = "metric:%d" % metric
            print (level+1)*INDENT + "%s: tos:%s, %s" % (cnt, tos, mstr)

        metrics[tos] = metric
        lsa = lsa[OSPF_METRIC_LEN:]

    return { "MASK"    : mask,
             "METRICS" : metrics
    }

def parseOspfLsaExt(lsa, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, lsa[:OSPF_LSAEXT_LEN])
    (mask, ) = struct.unpack(OSPF_LSAEXT, lsa[:OSPF_LSAEXT_LEN])
    if verbose > 0: print level*INDENT + "mask:%s" % id2str(mask)

    lsa = lsa[OSPF_LSAEXT_LEN:] ; cnt = 0 ; metrics = {}
    while len(lsa) > 0:

        if verbose > 1: print prtbin((level+1)*INDENT, lsa[:OSPF_LSAEXT_METRIC_LEN])
        (exttos, stub, metric, fwd, tag, ) =\
        struct.unpack(OSPF_LSAEXT_METRIC, lsa[:OSPF_LSAEXT_METRIC_LEN])
        ext = ((exttos & 0xf0) >> 7) * "E"
        tos = exttos & 0x7f

        metric = ((stub<<16) | metric)
        if verbose > 0:
            if metric == LS_STUB_RTR: mstr = "metric:STUB_ROUTER"
            elif metric > LS_INFINITY: mstr = "*** metric:%s > LS_INFINITY! ***" % metric
            elif metric == LS_INFINITY: mstr = "metric:LS_INFINITY"
            else: mstr = "metric:%d" % metric
            print (level+1)*INDENT +\
                  "%s: ext:%s, tos:%s, %s, fwd:%s, tag:0x%x" %(
                      cnt, ext, int2bin(tos), mstr, id2str(fwd), tag)

        metrics[tos] = { "EXT"    : ext,
                         "METRIC" : metric,
                         "FWD"    : fwd,
                         "TAG"    : tag,
                         }

        lsa = lsa[OSPF_LSAEXT_METRIC_LEN:]
        cnt += 1

    return { "MASK": mask,
             "METRICS": metrics,
             }

def parseOspfOpaque9(lsa, verbose=1, level=0):
    #TODO:unimplement
    return {"ODATA": lsa}
    pass

def parseOspfOpaque10(lsa, verbose=1, level=0):

    tlv = {}
    while len(lsa) > 0:

        (typ, length, ) = struct.unpack(OSPF_OPAQUE_TL, lsa[:OSPF_OPAQUE_TL_LEN])
        lsa = lsa[OSPF_OPAQUE_TL_LEN:]

        if typ == 1:        # Router Address
            (rtr, ) = struct.unpack('> L', lsa[:length])
            tlv['RA'] = rtr

        elif typ == 2:      # Link Information
            tlv['LNK'] = {}
            while length > 0:
                (subTyp, subLen, ) = struct.unpack(OSPF_OPAQUE_TL, lsa[:OSPF_OPAQUE_TL_LEN])
                lsa = lsa[OSPF_OPAQUE_TL_LEN:]
                if subTyp == 1:     # link type
                    (linkType,)  = struct.unpack('> B', lsa[:subLen])
                    #type 1 should pads 3 bytes
                    tlv['LNK']['T'] = linkType
                    subLen += 3
                elif subTyp == 2:   # link id
                    (linkId, ) = struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['ID'] = linkId
                elif subTyp == 3:   # local interface ip addr
                    (localIp, ) = struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['LIP'] = localIp
                elif subTyp == 4:   # remote interface ip addr
                    (remoteIp, ) = struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['RIP'] = remoteIp
                elif subTyp == 5:   # traffic engineer metric
                    (teMetric, ) = struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['TEMETRIC'] = teMetric
                elif subTyp == 6:   # maximum bandwidth
                    (maxBw, ) = struct.unpack('> f', lsa[:subLen])
                    tlv['LNK']['MAXBW'] = maxBw
                elif subTyp == 7:   # maximum reservable bandwidth
                    (maxRsvBw, ) = struct.unpack('> f', lsa[:subLen])
                    tlv['LNK']['MAXRSVBW'] = maxRsvBw
                elif subTyp == 8:   # unreservable bandwidth
                    (p0,p1,p2,p3,p4,p5,p6,p7, ) \
                        = struct.unpack('> f f f f f f f f', lsa[:subLen])
                    pri = (p0,p1,p2,p3,p4,p5,p6,p7)
                    tlv['LNK']['UNRSVBW'] = {}
                    for i in range(0, len(pri)):
                        tlv['LNK']['UNRSVBW']['P'+str(i)] = pri[i]
                elif subTyp == 9:   # administrative group
                    (adGrp, ) = struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['ADGRP'] = adGrp
                elif subTyp == 32770:   # IGP link metric ref: http://topic.cisco.com/news/cisco/cs/ospf/msg14256.html
                    (igpMetric, )= struct.unpack('> L', lsa[:subLen])
                    tlv['LNK']['IGPMETRIC'] = igpMetric
                elif subTyp == 32768:
                    (maxiRsvSubPoolBw, ) = struct.unpack('> f', lsa[:subLen])
                    tlv['LNK']['SUBPOOLBW'] = maxiRsvSubPoolBw
                elif subTyp == 32769:
                    (p0,p1,p2,p3,p4,p5,p6,p7, ) \
                        = struct.unpack('> f f f f f f f f', lsa[:subLen])
                    pri = (p0,p1,p2,p3,p4,p5,p6,p7)
                    tlv['LNK']['UNRSVSUBPOOLBW'] = {}
                    for i in range(0, len(pri)):
                        tlv['LNK']['UNRSVSUBPOOLBW']['P'+str(i)] = pri[i]
                else:
                    LOG.error('[ERROR] Type 10 LSA unknown sub-TLV, sub type is %s.' % subTyp)
                lsa = lsa[subLen:]
                length -= (subLen + OSPF_OPAQUE_TL_LEN)
        else:
            LOG.error('[ERROR] Type 10 LSA unknown TLV.')
        lsa = lsa[length:]

    return tlv

def parseOspfOpaque11(lsa, verbose=1, level=0):
    #TODO:unimplement
    return {"ODATA": lsa}
    pass

def parseOspfNssa(lsa, verbose=1, level=0):
    if verbose > 1: print prtbin(level*INDENT, lsa[:OSPF_LSAEXT_LEN])
    (mask, ) = struct.unpack(OSPF_LSAEXT, lsa[:OSPF_LSAEXT_LEN])
    if verbose > 0: print level*INDENT + "mask:%s" % id2str(mask)

    lsa = lsa[OSPF_LSAEXT_LEN:] ; cnt = 0 ; metrics = {}
    while len(lsa) > 0:

        if verbose > 1: print prtbin((level+1)*INDENT, lsa[:OSPF_LSAEXT_METRIC_LEN])
        (exttos, stub, metric, fwd, tag, ) =\
        struct.unpack(OSPF_LSAEXT_METRIC, lsa[:OSPF_LSAEXT_METRIC_LEN])
        ext = ((exttos & 0xf0) >> 7) * "E"
        tos = exttos & 0x7f

        metric = ((stub<<16) | metric)

        if verbose > 0:
            if metric == LS_STUB_RTR: mstr = "metric:STUB_ROUTER"
            elif metric > LS_INFINITY: mstr = "*** metric:%s > LS_INFINITY! ***" % metric
            elif metric == LS_INFINITY: mstr = "metric:LS_INFINITY"
            else: mstr = "metric:%d" % metric
            print (level+1)*INDENT +\
                  "%s: ext:%s, tos:%s, %s, fwd:%s, tag:0x%x" %(
                      cnt, ext, int2bin(tos), mstr, id2str(fwd), tag)

        metrics[tos] = { "EXT"    : ext,
                         "METRIC" : metric,
                         "FWD"    : fwd,
                         "TAG"    : tag,
                         }

        lsa = lsa[OSPF_LSAEXT_METRIC_LEN:]
        cnt += 1

    return { "MASK": mask,
             "METRICS": metrics,
             }

def parseOspfLsas(lsas, probe=None, msgHandler=None, verbose=1, level=0):

    rv = {}

    cnt = 0
    while len(lsas) > 0:
        cnt += 1
        rv[cnt] = {}

        if verbose > 0: print level*INDENT + "LSA %s" % cnt
        rv[cnt]["H"] = parseOspfLsaHdr(lsas[:OSPF_LSAHDR_LEN], verbose, level+1)

        t = rv[cnt]["H"]["T"]
        l = rv[cnt]["H"]["L"]
        rv[cnt]["T"] = t
        rv[cnt]["L"] = l

        cksum = ospf_lsa_checksum(lsas[:l])
        if cksum:
            if msgHandler is not None and probe is not None:
                # msgHandler.record_event(Event.str_event(
                #     'LSA_CHKSUM_ERR', probe,
                #     lsas[:l]
                # ))
                pass
            LOG.error('[ERROR] LSA checksum error.')
            lsas = lsas[l:]
            continue

        if t == LSA_TYPES["ROUTER"]:
            rv[cnt]["V"] = parseOspfLsaRtr(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["NETWORK"]:
            rv[cnt]["V"] = parseOspfLsaNet(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["SUMMARY (IP)"]:
            rv[cnt]["V"] = parseOspfLsaSummary(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["SUMMARY (ASBR)"]:
            rv[cnt]["V"] = parseOspfLsaSummary(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["EXTERNAL AS"]:
            rv[cnt]["V"] = parseOspfLsaExt(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)

        elif t == LSA_TYPES["NSSA"]:
            rv[cnt]["V"] = parseOspfNssa(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)

        elif t == LSA_TYPES["OPAQUE LINK LOCAL"]:
            rv[cnt]["V"] = parseOspfOpaque9(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["OPAQUE AREA LOCAL"]:
            rv[cnt]["V"] = parseOspfOpaque10(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)
        elif t == LSA_TYPES["OPAQUE AS LOCAL"]:
            rv[cnt]["V"] = parseOspfOpaque11(lsas[OSPF_LSAHDR_LEN:l], verbose, level+1)


        else:
            LOG.debug('[ERROR] Unknown LSU type.')

        lsas = lsas[l:]

    return rv

def parseOspfHello(msg, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, msg)
    (netmask, hello, opts, prio, dead, desig, bdesig) = struct.unpack(OSPF_HELLO, msg[:OSPF_HELLO_LEN])
    if verbose > 0:
        print level*INDENT +\
              "HELLO: netmask:%s, hello intvl:%s, opts:%s, prio:%s, dead intvl:%s" %\
              (id2str(netmask), hello, opts, prio, dead)
        print (level+1)*INDENT +\
              "designated rtr:%s, backup designated rtr:%s" %\
              (id2str(desig), id2str(bdesig))

    msg = msg[OSPF_HELLO_LEN:] ; nbor_len = struct.calcsize(">L") ; nbors = []

    while len(msg) > 0:
        if verbose > 1: print prtbin(level*INDENT, msg[:nbor_len])
        (nbor,) = struct.unpack(">L", msg[:nbor_len])
        if verbose > 0:
            print (level+1)*INDENT + "neighbour: %s" % (id2str(nbor),)
        nbors.append(nbor)
        msg = msg[nbor_len:]


    return { "NETMASK" : netmask,
             "HELLO"   : hello,
             "OPTS"    : parseOspfOpts(opts, verbose, level),
             "PRIO"    : prio,
             "DEAD"    : dead,
             "DESIG"   : desig,
             "BDESIG"  : bdesig,
             "NBORS"   : nbors
    }

def parseOspfDesc(msg, verbose=1, level=0):
#    print "DDES Length", len(msg)
    if verbose > 0: print prtbin(level*INDENT, msg)
    (mtu, opts, imms, ddseqno) = struct.unpack(OSPF_DESC, msg[:OSPF_DESC_LEN])

    init        = (imms & 0x04) >> 2
    more        = (imms & 0x02) >> 1
    masterslave = (imms & 0x01)
    if verbose > 0:
#    if False:
        print level*INDENT +\
              "DESC: mtu:%s, opts:%s, imms:%s%s%s%s, dd seqno:%s" %\
              (mtu, int2bin(opts), init*"INIT", more*" MORE",
               masterslave*" MASTER" + (1-masterslave)*" SLAVE",
               ddseqno)

    msg = msg[OSPF_DESC_LEN:]
    cnt = 0 ; lsas = {}
    while len(msg) > 0:
        cnt += 1
        if verbose > 0: print (level+1)*INDENT + "LSA %s" % cnt
        lsas[cnt] = parseOspfLsaHdr(msg[:OSPF_LSAHDR_LEN], verbose, level+1)
        msg = msg[OSPF_LSAHDR_LEN:]


    return { "MTU"         : mtu,
             "OPTS"        : parseOspfOpts(opts, verbose, level),
             "INIT"        : init,
             "MORE"        : more,
             "MS"          : masterslave,
             "DDSEQ"       : ddseqno,
             "LSAS"        : lsas
             }

def parseOspfLsReq(msg, verbose=1, level=0):

    error("### LSREQ UNIMPLEMENTED ###\n")
    return None

def parseOspfLsUpd(msg, probe, msgHandler=None, verbose=1, level=0):

    if verbose > 1: print prtbin(level*INDENT, msg[:OSPF_LSUPD_LEN])
    (nlsas, ) = struct.unpack(OSPF_LSUPD, msg[:OSPF_LSUPD_LEN])
    if verbose > 0:
        print level*INDENT + "LSUPD: nlsas:%s" % (nlsas)

    return { "NLSAS" : nlsas,
             "LSAS"  : parseOspfLsas(msg[OSPF_LSUPD_LEN:], probe, msgHandler, verbose, level+1),
             }

def parseOspfLsAck(msg, verbose=1, level=0):

    if verbose > 0: print level*INDENT + "LSACK"

    cnt = 0 ; lsas = {}
    while len(msg) > 0:
        cnt += 1
        if verbose > 0: print (level+1)*INDENT + "LSA %s" % cnt
        lsas[cnt] = parseOspfLsaHdr(msg[:OSPF_LSAHDR_LEN], verbose, level+1)
        msg = msg[OSPF_LSAHDR_LEN:]

    return { "LSAS"  : lsas}

def parseOspfMsg(msg, probe=None, msgHandler=None, verbose=1, level=0):

    iph = parseIpHdr(msg[:IP_HDR_LEN], verbose, level)

    if not iph:
        return None

    msg = msg[IP_HDR_LEN:]

#    print '------------ospf msg cksum, calc, dpkt',dpkt.in_cksum(msg)
    if dpkt.in_cksum(msg):
        LOG.error('[ERROR] OSPF header checksum error.')
        return None

    ospfh = parseOspfHdr(msg[:OSPF_HDR_LEN], verbose, level+1)
    rv = { "T": ospfh["TYPE"],
           "L": ospfh["LEN"],
           "H": iph,
           "V": ospfh,
           }

    if MSG_TYPES[ospfh["TYPE"]] == "HELLO":
        rv["V"]["V"] = parseOspfHello(msg[OSPF_HDR_LEN:ospfh["LEN"]], verbose, level+2)

    elif MSG_TYPES[ospfh["TYPE"]] == "DBDESC":
        rv["V"]["V"] = parseOspfDesc(msg[OSPF_HDR_LEN:ospfh["LEN"]], verbose, level+2)

    elif MSG_TYPES[ospfh["TYPE"]] == "LSREQ":
        rv["V"]["V"] = parseOspfLsReq(msg[OSPF_HDR_LEN:], verbose, level+1)

    elif MSG_TYPES[ospfh["TYPE"]] == "LSUPD":
        rv["V"]["V"] = parseOspfLsUpd(msg[OSPF_HDR_LEN:], probe, msgHandler, verbose, level+2)

    elif MSG_TYPES[ospfh["TYPE"]] == "LSACK":
        rv["V"]["V"] = parseOspfLsAck(msg[OSPF_HDR_LEN:], verbose, level+2)

    return rv


class OspfParser(object):

    @staticmethod
    def parse(packet, probe=None, msgHandler=None, verbose=0, level=0):
        try:
            (msg_len, msg) = len(packet), packet

        except Exception, e:
            LOG.error(e)
            return None

        try:
            rv = parseOspfMsg(msg, probe, msgHandler, verbose, level)
            return rv
        except Exception, e:
            LOG.error(e)
            LOG.error(traceback.format_exc())
            return None
