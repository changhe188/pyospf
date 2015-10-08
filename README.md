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

http://<ip>:7000/lsdb

### Get LSA by type

http://<ip>:7000/lsdb/router

http://<ip>:7000/lsdb/network

http://<ip>:7000/lsdb/summary

http://<ip>:7000/lsdb/sum-asbr

http://<ip>:7000/lsdb/external

http://<ip>:7000/lsdb/nssa

http://<ip>:7000/lsdb/opaque-9

http://<ip>:7000/lsdb/opaque-10

http://<ip>:7000/lsdb/opaque-11

### Get Statistics
 
http://<ip>:7000/stat