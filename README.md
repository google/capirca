#Capirca

Capirca is a tool designed to utilize common definitions of networks, services and high-level policy files to facilitate the development and manipulation of network access control lists (ACLs) for various platforms. It was developed by Google for internal use, and is now open source.


#Lint

Lint is a mechanism to analyze policies, network definitions, and service definitions to meet style criteria. The intention is for this tooling to be used as part of the policy development process to ensure consistency and make change-review easier. Lint rules can be enabled, disabled, and configured via a command-line specified YAML file. It is suggested to integrate the lint tooling into your software development code review tool to maximize the benefits.

##Running Lint

The linting comes in two different scripts - one for naming files (.net, .svc), and one for policy files. When linting a policy file, the naming definitions directory must be provided for the policies due to the way that the lint engine works.

Running the linters is quite simple:

```
$ ./namelint.py def/NETWORK.net
def/NETWORK.net -
  4 <Warning> 10.0.0.0/8 #  non-public indented by 10, not 4
  5 <Warning> 172.16.0.0/12 #  non-public indented by 10, not 4
...
$

$ ./pollint.py -d def policies/includes/untrusted-networks-blocking.inc
$
```

You can additionally specify a yaml configuration file - which will map to the configured parameters in the lint class:
```
$ cat example_lint.yaml
IndentEnforcer:
  enabled: false

RegexNameEnforcer:
    NETNAME: ".*"

$ ./namelint.py -c policies/lint/example_lint.yaml def/NETWORK.net
def/NETWORK.net -
  64 <Warning> 3ffe::/16 is an extremely large network, with more than 9 quintillion addresses
  65 <Warning> 5f00::/8 is an extremely large network, with more than 9 quintillion addresses
  66 <Warning> 2001:db8::/32 is an extremely large network, with more than 9 quintillion addresses
```

It is suggested that any environment-specific settings be changed via the YAML file, rather than changing the core code itself.

##Linter Style Guide

The provided defaults for the lint engine use the following style guide - it is by no means good for all use cases, but can be a good basis for bootstrapping your own style choices.

###Terms

* Term names should be all lower case and use dashes (-) to separate words
* Term names for IPv6 only rules should be appended with "-v6"
* Term names should be concise yet accurate and informative wherever possible; someone with no prior context should be able to get a general feeling for use the term serves upon reading its name and description. Use the "comment" field to elaborate if needed, but keep the term name useful
* Term names must be 31 or fewer total characters (limitation of some platforms)
* Term names generally **should not** have "allow-" or "permit-" in the name, it is understood that the term is being put in to allow something. Conversely, since terms denying traffic are rare, they **should** have "deny-" in the name.
* Terms in boilerplates (.inc files) should always start with the prefix "bp-"

**YES** - follow this!
```
term www-frontend {
    comment:: "#1234567 allow inbound Internet access to frontend clusters"
    <other fields omitted>
}

# In a boilerplate (.inc file), terms are prefixed by "bp-" to differentiate imported (.inc) terms versus .pol terms in the generated config
term bp-dns-return {
    comment:: "Allowing DNS return traffic for X VLAN"
    <other fields omitted>
}
```

**NO** - do not do this!
```
term WEB {
    <other fields omitted>
}

term permit_web {
    comment:: "HTTPS"
    <other fields omitted>
}

term allow-www-frontend {
    comment:: "WEB TRAFFIC"
    <other fields omitted>
}
```

###Network Name Definitions

* All UPPER case with UNDERSCORE (_) to separate words
* Single-address entries can be all on 1 line or broken out into 2 lines
* Multiple IPs & prefix lists: 1 per line, indented 4 spaces
* IPv6 only objects MUST be suffixed with _V6, and mixed objects MUST be suffixed by _ALL
* IPv4 only objects MUST NOT be suffixed with _V4
* Must begin with letter
* Avoid nesting network objects within other network objects where possible

**YES** - follow this!
```
# this is my main jumphost
JUMPHOST = 172.16.0.1/32

# these are all my jumphosts
ALL_JUMPHOSTS =
    172.16.0.1/32
    192.168.0.1/32
    10.0.0.1/32

# these are reserved networks
RFC_1918_AGGS =
    10.0.0.0/8    # I like this one
    192.168.0.0/16    # I never liked this network
    172.16.0.0/12    # I don't even know why we ever used this
```

**NO** - do not do this!
```
# avoid lower-case object names and use 4-space indents for the addresses
rfc-1918-aggs =
10.0.0.0/8
192.168.0.0/16
172.16.0.0/12

# avoid nesting single-address objects inside other objects when it's easily avoidable and don't start a group name with a number
1918_AGGS =
    net_10.0.0.0_8 # it's better to just use 10.0.0.0/8 here
    net_192.168.0.0_16
    net_172.16.0.0_12
```

###Service Name Definitions

* In general, do not mix tcp and udp in the same service group UNLESS the port numbers are shared across both protocols
* Use underscores (_) to separate words if needed
* Single ports and port ranges should begin with TCP or UDP
* Groups with multiple ports should be named in accordance with its function (eg, SNMP)
* Groups must have 1 port or range per line, indented 4 spaces
* Must begin with letter
* Syntax:
** PROTOCOL_PORT = PORT/protocol
** PROTOCOL_PORT1-PORT2 = PORT1-PORT2/protocol

**YES** - do this!
```
TCP_3074 = 3074/tcp
TCP_22 = 22/tcp
UDP_1-65535 = 1-65535/udp
SNMP =
    161/udp
    161/tcp
```

**NO** - please do not do this!
```
tcp3074 = 3074/tcp
tcp_3074 = 3074/tcp
my_port = 3074/tcp
databases_3306-3308 = 3306-3308/tcp
AUTHENTICATION =
  135/tcp
  135/udp
  137/udp
  138/udp
  139/tcp
  139/udp
  445/tcp
```
