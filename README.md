# pyospf

pyospf is an OSPF probe implementation in Python. It can be used for making OSPF adjacency and obtaining LSDB.

## Run it

Run it by executing following command.

```
$bin# ./pyospfd
```

## Get data using HTTP API

A server is running within the program.

it is listening the TCP port 7000 by default.

Try following APIs to get the OSPF data.

Noted: Use basic auth mode with the authentication data configured in config file when using the API. 

### Get LSDB

```
Get http://<bind_host>:<bind_port>/lsdb
```

### Get LSDB summary
 
```
Get http://<bind_host>:<bind_port>/lsdb_summary
```

### Get LSA by type

```
Get http://<bind_host>:<bind_port>/lsdb/router

Get http://<bind_host>:<bind_port>/lsdb/network

Get http://<bind_host>:<bind_port>/lsdb/summary

Get http://<bind_host>:<bind_port>/lsdb/sum-asbr

Get http://<bind_host>:<bind_port>/lsdb/external

Get http://<bind_host>:<bind_port>/lsdb/nssa

Get http://<bind_host>:<bind_port>/lsdb/opaque-9

Get http://<bind_host>:<bind_port>/lsdb/opaque-10

Get http://<bind_host>:<bind_port>/lsdb/opaque-11
```

### Get Statistics
 
```
Get http://<bind_host>:<bind_port>/stats
```

### Get probe status
 
```
Get http://<bind_host>:<bind_port>/probe
```

## Thanks

Special thanks to *PyRT(Python Routeing Toolkit)*. I used its OSPF module as the OSPF PDU parsers.