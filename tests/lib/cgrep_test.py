# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Unit tests for cgrep.

   Order doesn't matter for the purposes of these tests, so many
   actual and expected results are sorted/sets to prevent issues relating to the
   order in which items are returned.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import unittest

from lib import nacaddr
from lib import naming
from tools import cgrep


_NETWORK = """
#
# Sample naming defintions for network objects
#
RFC1918 = 10.0.0.0/8      # non-public
          172.16.0.0/12   # non-public
          192.168.0.0/16  # non-public

INTERNAL = RFC1918

LOOPBACK = 127.0.0.0/8  # loopback
           ::1/128       # ipv6 loopback

RFC_3330 = 169.254.0.0/16  # special use IPv4 addresses - netdeploy

RFC_6598 = 100.64.0.0/10   # Shared Address Space

LINKLOCAL = FE80::/10  # IPv6 link-local

SITELOCAL = FEC0::/10    # Ipv6 Site-local

MULTICAST = 224.0.0.0/4  # IP multicast
            FF00::/8     # IPv6 multicast

CLASS-E   = 240.0.0.0/4

RESERVED = 0.0.0.0/8           # reserved
           RFC1918
           LOOPBACK
           RFC_3330
           RFC_6598
           MULTICAST
           CLASS-E
           0000::/8            # reserved by IETF
           0100::/8            # reserved by IETF
           0200::/7            # reserved by IETF
           0400::/6            # reserved by IETF
           0800::/5            # reserved by IETF
           1000::/4            # reserved by IETF
           4000::/3            # reserved by IETF
           6000::/3            # reserved by IETF
           8000::/3            # reserved by IETF
           A000::/3            # reserved by IETF
           C000::/3            # reserved by IETF
           E000::/4            # reserved by IETF
           F000::/5            # reserved by IETF
           F800::/6            # reserved by IETF
           FC00::/7            # unique local unicast
           FE00::/9            # reserved by IETF
           LINKLOCAL           # link local unicast
           SITELOCAL           # IPv6 site-local

ANY = 0.0.0.0/0

# http://www.team-cymru.org/Services/Bogons/bogon-bn-agg.txt
# 22-Apr-2011
BOGON = 0.0.0.0/8
        192.0.0.0/24
        192.0.2.0/24
        198.18.0.0/15
        198.51.100.0/24
        203.0.113.0/24
        MULTICAST
        CLASS-E
        3FFE::/16      # 6bone
        5F00::/8       # 6bone
        2001:DB8::/32  # IPv6 documentation prefix

GOOGLE_PUBLIC_DNS_ANYCAST = 8.8.4.4/32               # IPv4 Anycast
                            8.8.8.8/32               # IPv4 Anycast
                            2001:4860:4860::8844/128 # IPv6 Anycast
                            2001:4860:4860::8888/128 # IPv6 Anycast
GOOGLE_DNS = GOOGLE_PUBLIC_DNS_ANYCAST


# The following are sample entires intended for us in the included
# sample policy file.  These should be removed.

WEB_SERVERS = 200.1.1.1/32  # Example web server 1
              200.1.1.2/32  # Example web server 2

MAIL_SERVERS = 200.1.1.4/32 # Example mail server 1
               200.1.1.5/32 # Example mail server 2

PUBLIC_NAT = 200.1.1.3/32   # Example company NAT address

NTP_SERVERS = 10.0.0.1/32   # Example NTP server
              10.0.0.2/32   # Example NTP server

TACACS_SERVERS = 10.1.0.1/32  # Example tacacs server
                 10.1.0.2/32  # Example tacacs server

INTERNAL_SERVER = 1.0.0.1/32

PUBLIC_SERVER = 100.0.0.1/32

INTERNAL_SERVERS = INTERNAL_SERVER

PUBLIC_SERVERS = PUBLIC_SERVER

SERVERS = INTERNAL_SERVERS
          PUBLIC_SERVERS

"""

_SERVICE = """
#
# Sample naming service definitions
#
WHOIS = 43/udp
SSH = 22/tcp
TELNET = 23/tcp
SMTP = 25/tcp
MAIL_SERVICES = SMTP
                ESMTP
                SMTP_SSL
                POP_SSL
TIME = 37/tcp 37/udp
TACACS = 49/tcp
DNS = 53/tcp 53/udp
BOOTPS = 67/udp   # BOOTP server
BOOTPC = 68/udp   # BOOTP client
DHCP = BOOTPS
       BOOTPC
TFTP = 69/tcp 69/udp
HTTP = 80/tcp
WEB_SERVICES = HTTP HTTPS
POP3 = 110/tcp
RPC = 111/udp
IDENT = 113/tcp 113/udp
NNTP = 119/tcp
NTP = 123/tcp 123/udp
MS_RPC_EPMAP = 135/udp 135/tcp
MS_137 = 137/udp
MS_138 = 138/udp
MS_139 = 139/tcp
IMAP = 143/tcp
SNMP = 161/udp
SNMP_TRAP = 162/udp
BGP = 179/tcp
IMAP3 = 220/tcp
LDAP = 389/tcp
LDAP_SERVICE = LDAP
               LDAPS
HTTPS = 443/tcp
MS_445 = 445/tcp
SMTP_SSL = 465/tcp
IKE = 500/udp
SYSLOG = 514/udp
RTSP = 554/tcp
ESMTP = 587/tcp
LDAPS = 636/tcp
IMAPS = 993/tcp
POP_SSL = 995/tcp
HIGH_PORTS = 1024-65535/tcp 1024-65535/udp
MSSQL = 1433/tcp
MSSQL_MONITOR = 1434/tcp
RADIUS = 1812/tcp 1812/udp
HSRP = 1985/udp
NFSD = 2049/tcp 2049/udp
NETFLOW = 2056/udp
SQUID_PROXY = 3128/tcp
MYSQL = 3306/tcp
RDP = 3389/tcp
IPSEC = 4500/udp
POSTGRESQL = 5432/tcp
TRACEROUTE = 33434-33534/udp
"""


class Namespace(object):

  def __init__(self, **kwargs):
    for arg in kwargs:
      setattr(self, arg, kwargs[arg])


class CgrepTest(unittest.TestCase):

  def setUp(self):
    self.db = naming.Naming(None)
    self.db.ParseServiceList(_SERVICE.split('\n'))
    self.db.ParseNetworkList(_NETWORK.split('\n'))

  #
  # test ip->token resolution (-i)
  #
  # 1.1.1.1 should only be in 'ANY'
  def test_one_ip(self):
    expected_results = [('ANY', ['0.0.0.0/0'])]
    ip = '1.1.1.1'
    results = cgrep.get_ip_parents(ip, self.db)
    self.assertEquals(results, expected_results)

  # 2001:db8::1 should only be in 'BOGON'
  def test_one_ipv6(self):
    expected_results = [('BOGON', ['2001:db8::/32'])]
    ip = '2001:db8::1'
    results = cgrep.get_ip_parents(ip, self.db)
    self.assertEquals(results, expected_results)

  # 1.1.1.1 should not be in CLASS-E
  def test_one_ip_fail(self):
    expected_results = [('CLASS-E', ['240.0.0.0/4'])]
    ip = '1.1.1.1'
    results = cgrep.get_ip_parents(ip, self.db)
    self.assertNotEquals(results, expected_results)

  # 2001:db8::1 should not be in LINKLOCAL
  def test_one_ipv6_fail(self):
    expected_results = [('LINKLOCAL', ['FE80::/10'])]
    ip = '2001:db8::1'
    results = cgrep.get_ip_parents(ip, self.db)
    self.assertNotEquals(results, expected_results)

  # 8.8.8.8 is in GOOGLE_PUBLIC_DNS_ANYCAST which is inside GOOGLE_DNS
  def test_one_ip_nested(self):
    expected_results = sorted((('GOOGLE_DNS', ['8.8.8.8/32']),
                               ('GOOGLE_DNS -> GOOGLE_PUBLIC_DNS_ANYCAST',
                                ['8.8.8.8/32']),
                               ('ANY', ['0.0.0.0/0'])))
    ip = '8.8.8.8'
    results = sorted(cgrep.get_ip_parents(ip, self.db))
    self.assertEquals(results, expected_results)

  # 2001:4860:4860::8844/128 is in GOOGLE_PUBLIC_DNS_ANYCAST which is
  # inside GOOGLE_DNS
  def test_one_ipv6_nested(self):
    expected_results = sorted((('GOOGLE_DNS', ['2001:4860:4860::8844/128']),
                               ('GOOGLE_DNS -> GOOGLE_PUBLIC_DNS_ANYCAST',
                                ['2001:4860:4860::8844/128'])))
    ip = '2001:4860:4860::8844/128'
    results = sorted(cgrep.get_ip_parents(ip, self.db))
    self.assertEquals(results, expected_results)

  # 1.0.0.1 is inside INTERNAL_SERVER, which is inside INTERNAL_SERVERS, which
  # is inside SERVERS
  def test_one_ip_multi_nested(self):
    expected_results = sorted((('INTERNAL_SERVERS -> INTERNAL_SERVER',
                                ['1.0.0.1/32']),
                               ('SERVERS -> INTERNAL_SERVER', ['1.0.0.1/32']),
                               ('SERVERS -> INTERNAL_SERVERS', ['1.0.0.1/32']),
                               ('SERVERS', ['1.0.0.1/32']),
                               ('ANY', ['0.0.0.0/0'])))
    ip = '1.0.0.1'
    results = sorted(cgrep.get_ip_parents(ip, self.db))
    self.assertEquals(results, expected_results)

  #
  # test 'ip in token' (-i -t)
  #
  # 8.8.8.8 is inside GOOGLE_DNS
  def test_ip_in_token(self):
    expected_results = r'8.8.8.8 is in GOOGLE_DNS'
    options = Namespace()
    options.ip = ('8.8.8.8',)
    options.token = ('GOOGLE_DNS')
    results = cgrep.compare_ip_token(options, self.db)
    self.assertEquals(results, expected_results)

  # 2001:4860:4860::8844 is inside GOOGLE_DNS
  def test_ipv6_in_token(self):
    expected_results = r'2001:4860:4860::8844 is in GOOGLE_DNS'
    options = Namespace()
    options.ip = ('2001:4860:4860::8844',)
    options.token = ('GOOGLE_DNS')
    results = cgrep.compare_ip_token(options, self.db)
    self.assertEquals(results, expected_results)

  # 69.171.239.12 is not in GOOGLE_DNS
  def test_ip_in_token_fail(self):
    expected_results = r'69.171.239.12 is _not_ in GOOGLE_DNS'
    options = Namespace()
    options.ip = ('69.171.239.12',)
    options.token = ('GOOGLE_DNS')
    results = cgrep.compare_ip_token(options, self.db)
    self.assertEquals(results, expected_results)

  # 2a03:2880:fffe:c:face:b00c:0:35 is not in GOOGLE_DNS
  def test_ipv6_in_token_fail(self):
    expected_results = r'2a03:2880:fffe:c:face:b00c:0:35 is _not_ in GOOGLE_DNS'
    options = Namespace()
    options.ip = ('2a03:2880:fffe:c:face:b00c:0:35',)
    options.token = ('GOOGLE_DNS')
    results = cgrep.compare_ip_token(options, self.db)
    self.assertEquals(results, expected_results)

  #
  # test network token compare (-c)
  #
  # these two tokens are identical and should contain the same nets
  def test_compare_same_token(self):
    expected_results = (
        (
            r'PUBLIC_NAT',
            r'PUBLIC_NAT',
            [
                nacaddr.IPv4('200.1.1.3/32')
            ],
        ),
        [
            r'200.1.1.3/32'
        ]
    )
    options = Namespace()
    options.cmp = ('PUBLIC_NAT', 'PUBLIC_NAT')
    results = cgrep.compare_tokens(options, self.db)
    self.assertEquals(results, expected_results)

  #
  # test network token encapsulations
  #
  def test_ip_contained(self):
    expected_results = True
    results = cgrep.check_encapsulated('network', 'RFC1918', 'RESERVED',
                                       self.db)
    self.assertEquals(results, expected_results)

  def test_ip_not_contained(self):
    expected_results = False
    results = cgrep.check_encapsulated('network', 'RESERVED', 'RFC1918',
                                       self.db)
    self.assertEquals(results, expected_results)

  def test_ipv6_contained(self):
    expected_results = True
    results = cgrep.check_encapsulated('network', 'LINKLOCAL', 'RESERVED',
                                       self.db)
    self.assertEquals(results, expected_results)

  def test_ipv6_not_contained(self):
    expected_results = False
    results = cgrep.check_encapsulated('network', 'RESERVED', 'LINKLOCAL',
                                       self.db)
    self.assertEquals(results, expected_results)

  #
  # test ip->object comparisons (-g)
  #
  # 8.8.8.8 is not present in object RESERVED and
  # 127.0.0.1 is not present in object GOOGLE_DNS and
  # the two IPs both exist in 'ANY'
  def test_group_diff(self):
    expected_results = sorted((
        ['ANY'],
        ['GOOGLE_DNS -> GOOGLE_PUBLIC_DNS_ANYCAST', 'GOOGLE_DNS'],
        ['RESERVED -> LOOPBACK', 'RESERVED']
    ))
    options = Namespace()
    options.gmp = ['8.8.8.8', '127.0.0.1']
    results = sorted(cgrep.group_diff(options, self.db))
    self.assertEquals(sorted(results[2]), sorted(expected_results[2]))

  # test to make sure two IPs share the same groups
  def test_group_diff_identical(self):
    expected_results = sorted((
        ['RESERVED', 'INTERNAL', 'RESERVED -> RFC1918',
         'ANY', 'INTERNAL -> RFC1918'],
        [],
        []
    ))
    options = Namespace()
    options.gmp = ['172.16.0.1', '192.168.0.1']
    results = sorted(cgrep.group_diff(options, self.db))
    self.assertEquals(sorted(results[2]), sorted(expected_results[2]))

  #
  # test token->ip(s) resolution (-o)
  #
  # resolve GOOGLE_DNS to the 4 given IPs
  def test_token_to_ips(self):
    expected_results = [
        (
            r'GOOGLE_DNS',
            [
                nacaddr.IPv4('8.8.4.4/32'),
                nacaddr.IPv4('8.8.8.8/32'),
                nacaddr.IPv6('2001:4860:4860::8844/128'),
                nacaddr.IPv6('2001:4860:4860::8888/128')
            ]
        )
    ]
    options = Namespace()
    options.obj = ('GOOGLE_DNS',)

    results = cgrep.get_nets(options.obj, self.db)
    self.assertEquals(results[0][0], expected_results[0][0])
    self.assertEquals(set(results[0][1]), set(expected_results[0][1]))

  # GOOGLE_DNS does not resole to the given IP
  def test_token_to_ip_fail(self):
    expected_results = [
        (
            r'GOOGLE_DNS',
            [
                nacaddr.IPv4('69.171.239.12/32'),
                nacaddr.IPv6('2a03:2880:fffe:c:face:b00c:0:35/128')
            ]
        )
    ]
    options = Namespace()
    options.obj = ('GOOGLE_DNS',)
    results = cgrep.get_nets(options.obj, self.db)
    # the network object name should match, but not the IPs contained within
    self.assertEquals(results[0][0], expected_results[0][0])
    self.assertNotEquals(set(results[0][1]), set(expected_results[0][1]))

  #
  # test service->port resolution (-s)
  #
  # "SSH" is just '22/tcp'
  def test_svc_to_port(self):
    expected_results = [
        (
            r'SSH',
            [
                '22/tcp'
            ]
        )
    ]
    options = Namespace()
    options.service = ('SSH',)
    results = cgrep.get_ports(options.service, self.db)
    self.assertEquals(results, expected_results)

  # "SSH" does not contain '23/tcp'
  def test_svc_to_port_fail(self):
    expected_results = [
        (
            r'SSH',
            [
                '23/tcp'
            ]
        )
    ]
    options = Namespace()
    options.svc = ('SSH',)
    results = cgrep.get_ports(options.svc, self.db)
    self.assertNotEquals(results, expected_results)

  #
  # test port->service object resolution (-p)
  #
  # '22/tcp' belongs to SSH
  def test_get_port_parents(self):
    expected_results = (r'22', r'tcp', ['SSH'])
    options = Namespace()
    options.port = ('22', 'tcp')
    results = cgrep.get_services(options, self.db)
    self.assertEquals(results, expected_results)

  # 22/tcp does not belong to TELNET
  def test_get_port_parents_fail(self):
    expected_results = (r'22', r'tcp', ['TELNET'])
    options = Namespace()
    options.port = ('22', 'tcp')
    results = cgrep.get_services(options, self.db)
    self.assertNotEquals(results, expected_results)

  # 33434/tcp should only be in HIGH_PORTS (not also TRACEROUTE)
  def test_get_port_parents_range_tcp(self):
    expected_results = (r'33434', r'tcp', ['HIGH_PORTS'])
    options = Namespace()
    options.port = ('33434', 'tcp')
    results = cgrep.get_services(options, self.db)
    self.assertEquals(results, expected_results)

  # 33434/udp should be in HIGH_PORTS and TRACEROUTE
  def test_get_port_parents_range_udp(self):
    expected_results = (r'33434', r'udp', ['HIGH_PORTS', 'TRACEROUTE'])
    options = Namespace()
    options.port = ('33434', 'udp')
    results = cgrep.get_services(options, self.db)
    self.assertEquals(results, expected_results)

  #
  # test IP validity
  #
  def test_invalid_ip(self):
    self.assertRaises(argparse.ArgumentTypeError,
                      cgrep.is_valid_ip, '10.0.0.256')

  def test_invalid_ipv6(self):
    self.assertRaises(argparse.ArgumentTypeError,
                      cgrep.is_valid_ip, '2001:db8::z')

  def test_valid_ips(self):
    arg = '8.8.8.8'
    results = cgrep.is_valid_ip(arg)
    self.assertEquals(results, arg)

  def test_valid_ips_v6(self):
    arg = '2001:4860:4860::8844'
    results = cgrep.is_valid_ip(arg)
    self.assertEquals(results, arg)


if __name__ == '__main__':
  unittest.main()
