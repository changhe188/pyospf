# !/usr/bin/env python
# -*- coding:utf-8 -*-


"""
basic config
"""


from oslo.config import cfg


CONF = cfg.CONF

probe_group = cfg.OptGroup(name='probe', title='Probe configuration.')

probe_opts = [
    cfg.StrOpt('router_id', help='OSPF Router ID'),
    cfg.StrOpt('area', default='0.0.0.0', help='OSPF Area ID',),
    cfg.FloatOpt('hello_interval', default=10.0, help='OSPF hello interval in seconds'),
    cfg.IntOpt('mtu', default=1500, help='OSPF link MTU'),
    cfg.StrOpt('ip', help='OSPF network interface IP address'),
    cfg.StrOpt('mask', help='OSPF network interface mask',),
    cfg.StrOpt('interface_name', help='OSPF network interface name'),
    cfg.StrOpt('link_type', help='OSPF network interface link type'),
    cfg.StrOpt('options', help='OSPF options'),
    cfg.IntOpt('rxmt_interval', help='OSPF retransmission interval')
]

database_group = cfg.OptGroup(name='database', title='Database configuration.')

database_opts = [
    cfg.StrOpt('server_ip', default='127.0.0.1', help='Database server IP address.'),
    cfg.StrOpt('server_port', default=27010, help='Database server port',)
]


message_group = cfg.OptGroup(name='message', title='Message bus configuration.')

message_opts = [

]

api_group = cfg.OptGroup(name='api', title='Restful API configuration.')

api_opts = [
    cfg.StrOpt('bind_host', default='127.0.0.1', help='Restful API bind IP address'),
    cfg.StrOpt('bind_port', default=7002, help='Restful API bind port',)
]

CONF.register_cli_opts(probe_opts, probe_group)
CONF.register_cli_opts(database_opts, database_group)
CONF.register_cli_opts(message_opts, message_group)
CONF.register_cli_opts(api_opts, api_group)

