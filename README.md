# pyospf

**pyospf** is an OSPF probe implementation in Python. It is designed for making OSPF adjacency with router to retrieve LSDB for real-time monitor or future analysis.

## Run it

Run it by executing following command. It will load the config file located in ./etc/pyospf.ini and then run **pyospf** in the front.

```
$ ./pyospfd
```

Apart from this, you can also use 'nohup' to run it in daemon.

## Retrieving data 

### using HTTP API

A HTTP server is running within the program. It is listening the TCP port 7000 by default.

Try following APIs to get the OSPF data. (All APIs use HTTP **GET** method.) 

**Noted**: Use basic auth mode with the authentication data configured in config file when using the API. 

#### Get LSDB

```
http://<bind_host>:<bind_port>/lsdb
```

#### Get LSDB summary
 
```
http://<bind_host>:<bind_port>/lsdb_summary
```

#### Get LSA by type

```
http://<bind_host>:<bind_port>/lsdb/router

http://<bind_host>:<bind_port>/lsdb/network

http://<bind_host>:<bind_port>/lsdb/summary

http://<bind_host>:<bind_port>/lsdb/sum-asbr

http://<bind_host>:<bind_port>/lsdb/external

http://<bind_host>:<bind_port>/lsdb/nssa

http://<bind_host>:<bind_port>/lsdb/opaque-9

http://<bind_host>:<bind_port>/lsdb/opaque-10

http://<bind_host>:<bind_port>/lsdb/opaque-11
```

#### Get Statistics
 
```
http://<bind_host>:<bind_port>/stats
```

#### Get probe status
 
```
http://<bind_host>:<bind_port>/probe
```

### Store data in database

We plan to implement this in near future.

## Thanks

Special thanks to **PyRT(Python Routeing Toolkit)**. Its OSPF PDU parser is used as same as in pyospf.