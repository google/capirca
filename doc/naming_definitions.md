# Introduction
The naming definitions provide the network and service "address books" that are used in the creation of policy files. Naming definitions are usually stored in a single directory, and consist of two or more files. Each file must end in either a `.net` or `.svc` extension, specifying a network or services definitions files.

Multiple network and service definitions files may be created. The use of multiple files may be done to facilitate grouping of related definitions, or to utilize filesystem permissions to restrict or permit the editing of files by specific groups.

The use of a revision control system, such as perforce or subversion, is a recommended way to ensure historical change control and tracking of contributor changes.

## Format of Files
Each network or service definition file has a very simple structure. A token is defined, followed by an equal sign, then followed by a definition and optional description field.

For example, here is an example of a service definition:

```
DNS = 53/tcp  # transfers
      53/udp  # queries
```

Likewise, here is an example of a network definition:

```
INTERNAL = 192.168.0.0/16  # company DMZ networks
           172.16.0.0/12   # company remote offices
           10.0.0.0/8      # company production networks
```

Nesting of tokens is also permitted. Below are examples of nested service and network definitions:

```
HTTP = 80/tcp               # common web
HTTPS = 443/tcp             # SSL web
HTTP_8080 = 8080/tcp        #  web on non-standard port
WEB_SERVICES = HTTP HTTP_8080 HTTPS  # all our web services
DB_SERVICES = 3306/tcp      # allow db access
              HTTPS         # and SSL access
NYC_NETWORK = 200.1.1.0/24  # New York office
ATL_NETWORK = 200.2.1.0/24  # Atlanta office
DEN_NETWORK = 200.5.1.0/24  # Denver office
REMOTE_OFFICES = NYC_NETWORK
                 ATL_NETWORK
                 DEN_NETWORK
```

Network definitions can also contain a mix of both IPv4 and IPv6 addresses:

```
LOOPBACK = 127.0.0.1/32          # loopback in IPv4
           ::1/128               # loopback in IPv6
LINKLOCAL = FE80::/10            # IPv6 link local address
NYC_NETWORK = 172.16.1.0/24      # NYC IPv4
              2620:0:10A1::/48   # NYC IPv6
```
