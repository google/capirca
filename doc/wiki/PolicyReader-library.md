# Introduction

The policy reader library is library that allows other code to easily examine
policy source files.

The policy library only reads policies for the purpose of rendering objects for
passing to generators.

For some tools, we needed to be able to easily examine the various filters and
terms for programmatically.

Policy reader renders simple objects that allow us to do this handy for a
variety of tools, such as rendering policies in a Web UI for example

## Overview

Import the policyreader library from the top Capirca directory.

Load a policy and set of definitions:

```py
p = policyreader.Policy('policy_path', 'definitions_path')
```

Print out the policy:

```
print(p)
```

Search for terms matching specific criteria:

```
>>> p.Matches(src='1.1.1.1', dport='53/udp')
[[0, 1]]
```

The result tuple indicates that a matching rule was found in Filter 0 at Term 1.
You can print out the name of this term with:

```
print p.filter[0].term[1].name
accept-to-honestdns
```

You can also display this entire specific term using:

```
print  p.filter[0].term[1]
  Term: accept-to-honestdns
  Source-address::
  Destination-address:: GOOGLE_DNS
  Source-port::
  Destination-port:: DNS
  Protocol:: udp
  Option::
  Action:: accept
```

You can examine the values of addresses or services as follows:

```
print p.defs.GetNet('GOOGLE_DNS')
[IPv4('8.8.4.4/32'), IPv4('8.8.8.8/32'), IPv6('2001:4860:4860::8844/128'), IPv6('2001:4860:4860::8888/128')]
>>> print p.defs.GetService('DNS')
['53/tcp', '53/udp']
```

## Example Usage

```
$ python
>>> from lib import policyreader
>>> p=policyreader.Policy('./policies/sample_cisco_lab.pol', './def/')
>>> print p
Filter: allowtointernet
-----------------------
  Term: accept-dhcp
  Source-address::
  Destination-address::
  Source-port::
  Destination-port:: DHCP
  Protocol:: udp
  Option::
  Action:: accept
  Term: accept-to-honestdns
  Source-address::
  Destination-address:: GOOGLE_DNS
  Source-port::
  Destination-port:: DNS
  Protocol:: udp
  Option::
  Action:: accept
  Term: accept-tcp-replies
  Source-address::
  Destination-address:: INTERNAL
  Source-port::
  Destination-port::
  Protocol:: tcp
  Option:: tcp-established
  Action:: accept
  Term: deny-to-internal
  Source-address::
  Destination-address:: INTERNAL
  Source-port::
  Destination-port::
  Protocol::
  Option::
  Action:: deny
  Term: deny-to-specific_hosts
  Source-address::
  Destination-address:: WEB_SERVERS MAIL_SERVERS
  Source-port::
  Destination-port::
  Protocol::
  Option::
  Action:: deny
  Term: default-permit
  Source-address::
  Destination-address::
  Source-port::
  Destination-port::
  Protocol::
  Option::
  Action:: accept
>>>
>>> p.defs.GetNet('INTERNAL')
[IPv4('10.0.0.0/8'), IPv4('172.16.0.0/12'), IPv4('192.168.0.0/16')]
>>>
>>> p.defs.GetService('DNS')
['53/tcp', '53/udp']
```
