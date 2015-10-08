#!/usr/bin/env python
# -*- coding:utf-8 -*-


import threading

neighborLock = threading.RLock()
datetimeLock = threading.RLock()

ALL_SPF_ROUTER = '224.0.0.5'
ALL_D_ROUTER = '224.0.0.6'
MAXAGE = 3600
MIN_AGE_DIFF = 900
MIN_LS_ARRIVAL = 1
MAX_SEQ_NO = 0x7fffffff
ALLOW_LS_TYPE = [1, 2, 3, 4, 5, 7, 9, 10, 11]

#OSPF Interface State Machine Status.
ISM_STATE = {
    "ISM_DependUpon": 0,
    "ISM_Down": 1,
    "ISM_Loopback": 2,
    "ISM_Waiting": 3,
    "ISM_PointToPoint": 4,
    "ISM_DROther": 5,
    "ISM_Backup": 6,
    "ISM_DR": 7,
    "OSPF_ISM_STATE_MAX": 8
}

# OSPF Interface State Machine Event.
ISM_EVENT = {
    "ISM_NoEvent": 0,
    "ISM_InterfaceUp": 1,
    "ISM_WaitTimer": 2,
    "ISM_BackupSeen": 3,
    "ISM_NeighborChange": 4,
    "ISM_LoopInd": 5,
    "ISM_UnloopInd": 6,
    "ISM_InterfaceDown": 7,
    "OSPF_ISM_EVENT_MAX": 8
}

#OSPF Neighbor State Machine State.
NSM_STATE = {
    "NSM_DependUpon": 0,
    "NSM_Deleted": 1,
    "NSM_Down": 2,
    "NSM_Attempt": 3,
    "NSM_Init": 4,
    "NSM_TwoWay": 5,
    "NSM_ExStart": 6,
    "NSM_Exchange": 7,
    "NSM_Loading": 8,
    "NSM_Full": 9,
    "OSPF_NSM_STATE_MAX": 10
}

#OSPF Neighbor State Machine Event.
NSM_EVENT = {
    "NSM_NoEvent": 0,
    "NSM_PacketReceived": 1,  # HelloReceived in the protocol
    "NSM_Start": 2,
    "NSM_TwoWayReceived": 3,
    "NSM_NegotiationDone": 4,
    "NSM_ExchangeDone": 5,
    "NSM_BadLSReq": 6,
    "NSM_LoadingDone": 7,
    "NSM_AdjOK": 8,
    "NSM_SeqNumberMismatch": 9,
    "NSM_OneWayReceived": 10,
    "NSM_KillNbr": 11,
    "NSM_InactivityTimer": 12,
    "NSM_LLDown": 13,
    "OSPF_NSM_EVENT_MAX": 14
}
