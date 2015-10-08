#!/usr/bin/env python
# -*- coding:utf-8 -*-


import signal
import time
import logging

from ospfArea import *
from ospfReceiver import *
from basics.ospfSock import *
from basics.variable import *
from pyospf.utils.timer import *
from pyospf.utils import util

# from sender.backendMsgHandler import *


LOG = logging.getLogger(__name__)


class OspfInstance(object):

    def __init__(self, config, pid=1, snapshot_interval=90, debug=False):

        # self.cli = True             # switch of CLI
        # self.cliUpdateTimer = None
        # #this interval should not be set too small to avoid too frequently update.
        # self.cliUpdateInterval = update_interval

        self.area_list = dict()
        self.backbone = None        # not used
        self.virtual_link = None     # not used
        self.external_router = list()    # not used

        self.as_external_lsa = dict()     # type-5 lsa list
        self.nssa_lsa = dict()           # type-7 lsa list
        self.opaque11_lsa = dict()       # type-11 lsa list

        # self.sm = sharedMem
        self.config = config
        self.process_id = pid
        # self.msgHandler = BackendMsgHandler(self.processId, self)     # handler for sending message to backend server
        self.lsdb_snapshot_timer = None
        self.lsdb_snapshot_interval = snapshot_interval

        self.rid = self.config['router_id']
        # self.macAddr = self.config['etherAddr']
        self.interface_mame = self.config['interface']
        self.local_ip = self.config['ip']

        #Check config reasonable
        if self.config['hello_interval'] < 1 or self.config['hello_interval'] > 65535:
            LOG.critical('[OSPF Instance] Hello interval is beyond limitation.')
            return

        #Attention: now the probe can only connect to one area, so areaList has no meaning.
        #TODO: to handle multi area adjacency, area need to be modified
        self.area = OspfArea(self)
        self.area_list[self.area.area_id] = self.area

        #filter = 'ip proto 89 and not ether src ' + self.macAddr
        self.oRecv = OspfReceiver(self.area.interface, self.area.interface.nbrList)
        self._sock = None   # socket for receiving ospf packets

        #Statistics for sending packets
        self.totalSendPacketCount = 0
        self.sendHelloCount = 0
        self.sendDDCount = 0
        self.sendLSRCount = 0
        self.sendLSUCount = 0
        self.sendLSAckCount = 0

        #dataset to store updated lsa sending to backend
        self._updatedLsa = {
            'router': dict(),
            'network': dict(),
            'summary': dict(),
            'sum-asbr': dict(),
            'external': dict(),
            'nssa': dict(),
            'opaque-9': dict(),
            'opaque-10': dict(),
            'opaque-11': dict(),
            }

        #dataset to store deleted lsa sending to backend
        self._delLsa = {'router': dict(),
                'network': dict(),
                'summary': dict(),
                'sum-asbr': dict(),
                'external': dict(),
                'nssa': dict(),
                'opaque-9': dict(),
                'opaque-10': dict(),
                'opaque-11': dict(),
        }

        # self.signalCount = 0    # counters for terminal signal

        self.debug = debug

    def run(self):
        """
        Main thread
        """
        #start backend message sender
        # self.msgHandler.start()

        #gives an interface up message to ism
        self.area.interface.fire('ISM_InterfaceUp')
        if self.area.interface.state == ISM_STATE['ISM_Down']:
            LOG.error('[OSPF Instance] Interface up failed.')
            return

        #start to listen ospf port by sniffer
        #self.oRecv.init()

        #open a socket to listen ospf port to avoid sending icmp protocol unreachable
        self._sock = OspfSock()
        self._sock.bind_ospf_multicast_group(self.interface_mame)
        self._sock.add_ospf_multicast_group(self.local_ip)

        #bind signal handler to handle terminal signal
        signal.signal(signal.SIGTERM, self.term_handler)
        signal.signal(signal.SIGINT, self.term_handler)

        #start a thread to update shared-memory with CLI
        # self.update()
        # self.cliUpdateTimer = Timer(self.cliUpdateInterval, self.update)
        # self.cliUpdateTimer.start()

        #start a thread to send lsdb snapshot to backend
        self.lsdb_snapshot_timer = Timer(self.lsdb_snapshot_interval, self.lsdb_snapshot)
        self.lsdb_snapshot_timer.start()

        while not self.debug:
            (data, src) = self._sock.recv()
            (srcIp, port) = src
            if srcIp == self.local_ip:       # filter to drop all packets from myself
                continue

            self.oRecv.ospf_handler(data, time.time())
            #Capture packets
            #self.oRecv.dispatch()

    def term_handler(self, a, b):
        LOG.debug('[OSPF Instance] Signal %s is received.' % str(a))
        self.exit()

    def exit(self):
        self.msgHandler.close_msg_server()
        self._sock.drop_ospf_multicast_group(self.local_ip)
        self._sock.close()
        LOG.info('[OSPF Instance] Program exit.')
        exit(0)

    # def update(self):
    #     """
    #     Update shared memory with CLI process.
    #     This function should be called every time when the relevant elements in the shared-memory changed.
    #     """
    #     if not self.cli:
    #         return
    #     if self.sm is None:
    #         self.cli = False
    #         _logger.warn('[Update] CLI shared memory failed.')
    #         return
    #     else:
    #         _logger.debug('[Update] start: %s:%f' %
    #                        (time.strftime('%H:%M', time.localtime(time.time())), time.time() % 60))
    #
    #         ospfData = self.sm
    #         #ospf_data is like: {'database':{'router':{},'network':{},'summary':{},,'sum-asbr':{},'external':{},
    #         #                   'opaque-9':{},'opaque-10':{},'opaque-11':{}, 'nssa':{}},'adj':{},'statistics':{}}
    #
    #         #update database
    #         lsdbLock.acquire()
    #         ospfData['database'] = {'router': self.area.routerLsa,
    #                                 'network': self.area.networkLsa,
    #                                 'summary': self.area.summaryLsa,
    #                                 'sum-asbr': self.area.summaryAsbrLsa,
    #                                 'external': self.as_external_lsa,
    #                                 'nssa': self.nssa_lsa,
    #                                 'opaque-9': self.area.opaque9Lsa,
    #                                 'opaque-10': self.area.opaque10Lsa,
    #                                 'opaque-11': self.opaque11_lsa}
    #
    #         #update adj
    #         nbr = {}
    #
    #         for rid in self.area.interface.nbrList:
    #             if self.area.interface.nbrList[rid].src == self.area.interface.drIp:
    #                 intfs = 'DR'
    #             elif self.area.interface.nbrList[rid].src == self.area.interface.bdrIp:
    #                 intfs = 'BDR'
    #             else:
    #                 if self.area.interface.linkType == 'Broadcast':
    #                     intfs = 'DOther'
    #                 else:
    #                     intfs = '-'
    #
    #             nbrs = util.find_key(NSM_STATE, self.area.interface.nbrList[rid].state)[0]
    #             nbr[util.int2ip(rid)] = intfs + '/' + nbrs
    #         ospfData['adj'] = nbr
    #
    #         #update statistics
    #         txSt = {'Total': self.totalSendPacketCount,
    #                 'Hello': self.sendHelloCount,
    #                 'DB Desc': self.sendDDCount,
    #                 'LSR': self.sendLSRCount,
    #                 'LSU': self.sendLSUCount,
    #                 'LSAck': self.sendLSAckCount}
    #
    #         rxSt = {'Total Received': self.oRecv.totalReceivedPacketCount,
    #                 'Total Handled': self.oRecv.totalHandledPacketCount,
    #                 'Hello': self.oRecv.recvHelloCount,
    #                 'DB Desc': self.oRecv.recvDDCount,
    #                 'LSR': self.oRecv.recvLSRCount,
    #                 'LSU': self.oRecv.recvLSUCount,
    #                 'LSAck': self.oRecv.recvLSAckCount}
    #
    #         ospfData['statistics'] = {'RX': rxSt, 'TX': txSt}
    #
    #         self.sm = ospfData
    #         lsdbLock.release()
    #         _logger.debug('[Update] stop: %s:%f' %
    #                        (time.strftime('%H:%M', time.localtime(time.time())), time.time() % 60))

    def save_lsa_update(self, lsa):
        ls, tp, aid, id, adv = self.generate_lsa_key(lsa)
        updateLsaLock.acquire()
        self._updatedLsa[self.lsa_tp_num2word(tp)][ls] = lsa
        updateLsaLock.release()

    def save_lsa_del(self, lsa):
        ls, tp, aid, id, adv = self.generate_lsa_key(lsa)
        delLsaLock.acquire()
        self._delLsa[self.lsa_tp_num2word(tp)][ls] = lsa
        delLsaLock.release()

    @staticmethod
    def generate_lsa_key(lsa):
        tp, id, adv, aid = lsa['H']['T'], lsa['H']['LSID'], lsa['H']['ADVRTR'], lsa['AREA']
        if int(lsa['H']['T']) == 5:
            ls = str((tp, id, adv))
        else:
            ls = str((tp, aid, id, adv))
        return ls, tp, aid, id, adv

    def send_put_lsa(self):
        updateLsaLock.acquire()
        lsaCnt = 0
        for lsaType in self._updatedLsa:
            lsaCnt += len(self._updatedLsa[lsaType])
        if lsaCnt > 0:
            self.msgHandler.send_message('LS', 'PUT', self._updatedLsa, needRecord=True)
            _logger.info('[OSPF Instance] Probe %s will send %s LSA update(s) to backend.' %
                         (self.process_id, lsaCnt))
        self._updatedLsa = {'router': dict(),
                            'network': dict(),
                            'summary': dict(),
                            'sum-asbr': dict(),
                            'external': dict(),
                            'nssa': dict(),
                            'opaque-9': dict(),
                            'opaque-10': dict(),
                            'opaque-11': dict(),
                            }
        updateLsaLock.release()

    def send_del_lsa(self):
        delLsaLock.acquire()
        self.msgHandler.send_message('LS', 'DEL', self._delLsa, needRecord=True)
        lsaCnt = 0
        for lsaType in self._delLsa:
            lsaCnt += len(self._delLsa[lsaType])
        _logger.info('[OSPF Instance] Will send %s LSA delete(s) to backend.' % lsaCnt)
        self._delLsa = {'router': dict(),
                'network': dict(),
                'summary': dict(),
                'sum-asbr': dict(),
                'external': dict(),
                'nssa': dict(),
                'opaque-9': dict(),
                'opaque-10': dict(),
                'opaque-11': dict(),
        }
        delLsaLock.release()

    @staticmethod
    def lsa_tp_num2word(tp):
        """
        Translate LSA type number to word.
        """
        typeWord = {1: 'router',
                    2: 'network',
                    3: 'summary',
                    4: 'sum-asbr',
                    5: 'external',
                    7: 'nssa',
                    9: 'opaque-9',
                    10: 'opaque-10',
                    11: 'opaque-11', }
        tp = int(tp)
        if typeWord.has_key(tp):
            return typeWord[tp]
        else:
            return None

    def lsdb_snapshot(self):
        """
        Generate LSDB snapshot contains all LSA key to send to backend.
        """
        lsdbLock.acquire()
        lsdb = {'router': self.area.router_lsa,
                'network': self.area.network_lsa,
                'summary': self.area.summary_lsa,
                'sum-asbr': self.area.summary_asbr_lsa,
                'external': self.as_external_lsa,
                'nssa': self.nssa_lsa,
                'opaque-9': self.area.opaque9_lsa,
                'opaque-10': self.area.opaque10_lsa,
                'opaque-11': self.opaque11_lsa
        }
        #Translate the tuple lsa key to string
        strKeyLsdbSnapshot = dict()
        _logger.debug('[OSPF Instance] Start to generate an LSDB snapshot message.')
        for lsType in lsdb:
            if not strKeyLsdbSnapshot.has_key(lsType):
                strKeyLsdbSnapshot[lsType] = list()
            for lsa in lsdb[lsType]:
                strKeyLsdbSnapshot[lsType].append(str(lsa))
        lsdbLock.release()
        self.msgHandler.send_message('CSNP', 'PUT', strKeyLsdbSnapshot, needResend=False)
        _logger.info('[OSPF Instance] Generated an LSDB snapshot message.')

    def del_all_lsa(self):
        """
        Delete all LSA in LSDB.
        """
        lsdbLock.acquire()
        lsdb = {'router': self.area.router_lsa,
                'network': self.area.network_lsa,
                'summary': self.area.summary_lsa,
                'sum-asbr': self.area.summary_asbr_lsa,
                'external': self.as_external_lsa,
                'nssa': self.nssa_lsa,
                'opaque-9': self.area.opaque9_lsa,
                'opaque-10': self.area.opaque10_lsa,
                'opaque-11': self.opaque11_lsa
        }
        for lsaTyp in lsdb:
            for lsa in lsdb[lsaTyp]:
                self.save_lsa_del(lsdb[lsaTyp][lsa])
        self.send_del_lsa()
        for lsaTyp in lsdb:
            lsdb[lsaTyp] = dict()
        lsdbLock.release()
        _logger.info('[OSPF Instance] Delete all LSAs in LSDB.')