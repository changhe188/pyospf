# pyospf

pyospf is an OSPF implementation in Python. It can be used for making OSPF adjacency and obtaining LSDB.

## Run it

Run it by executing following command.

```
$bin/ ./pyospfd
```

## Get data using HTTP API

A server is running on TCP port 7000(defualt).

Try following APIs to get the OSPF data.

### Get LSDB

```
Get http://<ip>:7000/lsdb
```

### Get LSA by type

```
Get http://<ip>:7000/lsdb/router

Get http://<ip>:7000/lsdb/network

Get http://<ip>:7000/lsdb/summary

Get http://<ip>:7000/lsdb/sum-asbr

Get http://<ip>:7000/lsdb/external

Get http://<ip>:7000/lsdb/nssa

Get http://<ip>:7000/lsdb/opaque-9

Get http://<ip>:7000/lsdb/opaque-10

Get http://<ip>:7000/lsdb/opaque-11
```

### Get Statistics
 
```
Get http://<ip>:7000/stat
```