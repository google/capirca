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

"""Cisco generator."""

import datetime
import ipaddress
from typing import cast, Union

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import summarizer


_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
}

_COMMENT_MAX_WIDTH = 70


# generic error class
class Error(Exception):
  """Generic error class."""


class CiscoDuplicateTermError(Error):
  """Raised on duplicate term names."""


class CiscoNextIpError(Error):
  """Raised when next-ip is misconfigured."""


class UnsupportedCiscoAccessListError(Error):
  """Raised when we're give a non named access list."""


class StandardAclTermError(Error):
  """Raised when there is a problem in a standard access list."""


class ExtendedACLTermError(Error):
  """Raised when there is a problem in an extended access list."""


class TermStandard:
  """A single standard ACL Term."""

  def __init__(self, term, filter_name, platform='cisco', verbose=True):
    self.term = term
    self.filter_name = filter_name
    self.platform = platform
    self.options = []
    self.logstring = ''
    self.dscpstring = ''
    self.verbose = verbose
    # sanity checking for standard acls
    if self.term.protocol:
      raise StandardAclTermError(
          'Standard ACLs cannot specify protocols')
    if self.term.icmp_type:
      raise StandardAclTermError(
          'ICMP Type specifications are not permissible in standard ACLs')
    if (self.term.source_address
        or self.term.source_address_exclude
        or self.term.destination_address
        or self.term.destination_address_exclude):
      raise StandardAclTermError(
          'Standard ACLs cannot use source or destination addresses')
    if self.term.option:
      raise StandardAclTermError(
          'Standard ACLs prohibit use of options')
    if self.term.source_port or self.term.destination_port:
      raise StandardAclTermError(
          'Standard ACLs prohibit use of port numbers')
    if self.term.logging:
      logging.warning(
          'WARNING: Standard ACL logging is set in filter %s, term %s and '
          'may not implemented on all IOS versions', self.filter_name,
          self.term.name)
      self.logstring = ' log'
    if self.term.dscp_match:
      logging.warning(
          'WARNING: dscp-match is set in filter %s, term %s and may not be '
          'implemented on all IOS version', self.filter_name, self.term.name)
      self.dscpstring = ' dscp' + self.term.dscp_match

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self.platform not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self.platform in self.term.platform_exclude:
        return ''

    ret_str = []

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim[0] == self.platform:
          ret_str.append(str(next_verbatim[1]))
      return '\n'.join(ret_str)

    v4_addresses = [x for x in self.term.address if
                    not isinstance(x, nacaddr.IPv6)]
    if self.filter_name.isdigit():
      if self.verbose:
        ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                     self.term.name))
        comments = aclgenerator.WrapWords(self.term.comment,
                                          _COMMENT_MAX_WIDTH)
        for comment in comments:
          ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                       comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append('access-list %s %s %s%s%s' % (self.filter_name,
                                                         action,
                                                         addr.network_address,
                                                         self.logstring,
                                                         self.dscpstring))
          else:
            ret_str.append('access-list %s %s %s %s%s%s' % (
                self.filter_name,
                action,
                addr.network_address,
                addr.hostmask,
                self.logstring,
                self.dscpstring))
      else:
        ret_str.append('access-list %s %s %s%s%s' % (self.filter_name,
                                                     action,
                                                     'any',
                                                     self.logstring,
                                                     self.dscpstring))
    else:
      if self.verbose:
        ret_str.append(' remark ' + self.term.name)
        comments = aclgenerator.WrapWords(self.term.comment,
                                          _COMMENT_MAX_WIDTH)
        if comments and comments[0]:
          for comment in comments:
            ret_str.append(' remark ' + str(comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append(' %s host %s%s%s' % (action,
                                                addr.network_address,
                                                self.logstring,
                                                self.dscpstring))
          elif self.platform == 'arista':
            ret_str.append(' %s %s/%s%s%s' % (action,
                                              addr.network_address,
                                              addr.prefixlen,
                                              self.logstring,
                                              self.dscpstring))
          else:
            ret_str.append(' %s %s %s%s%s' % (action,
                                              addr.network_address,
                                              addr.hostmask,
                                              self.logstring,
                                              self.dscpstring))
      else:
        ret_str.append(' %s %s%s%s' % (action,
                                       'any',
                                       self.logstring,
                                       self.dscpstring))

    return '\n'.join(ret_str)


class ObjectGroup:
  """Used for printing out the object group definitions.

  since the ports don't store the token name information, we have
  to fudge their names.  ports will be written out like

    object-group port <low_port>-<high_port>
      range <low-port> <high-port>
    exit

  where as the addressess can be written as

    object-group address ipv4 first-term-source-address
      172.16.0.0
      172.20.0.0 255.255.0.0
      172.22.0.0 255.128.0.0
      172.24.0.0
      172.28.0.0
    exit
  """

  def __init__(self, af=4):
    self.filter_name = ''
    self.terms = []
    self.af = af

  @property
  def valid(self):
    return bool(self.terms)

  def AddTerm(self, term):
    self.terms.append(term)

  def AddName(self, filter_name):
    self.filter_name = filter_name

  def __str__(self):
    ret_str = ['\n']
    # netgroups will contain two-tuples of group name string and family int.
    netgroups = set()
    ports = {}

    for term in self.terms:
      # I don't have an easy way get the token name used in the pol file
      # w/o reading the pol file twice (with some other library) or doing
      # some other ugly hackery. Instead, the entire block of source and dest
      # addresses for a given term is given a unique, computable name which
      # is not related to the NETWORK.net token name.  that's what you get
      # for using cisco, which has decided to implement its own meta language.

      # Create network object-groups
      addr_type = ('source_address', 'destination_address')

      for source_or_dest in addr_type:
        addrs = term.GetAddressOfVersion(source_or_dest, self.af)
        if addrs:
          net_def_name = addrs[0].parent_token
          # We have addresses for this family and have not already seen it.
          if (net_def_name, self.af) not in netgroups:
            netgroups.add((net_def_name, self.af))
            ret_str.append('object-group network ipv%d %s' % (
                self.af, net_def_name))
            for addr in addrs:
              ret_str.append(' %s/%s' % (addr.network_address,
                                         addr.prefixlen))
            ret_str.append('exit\n')

      # Create port object-groups
      for port in term.source_port + term.destination_port:
        if not port:
          continue
        port_key = '%s-%s' % (port[0], port[1])
        if port_key not in ports:
          ports[port_key] = True
          ret_str.append('object-group port %s' % port_key)
          if port[0] != port[1]:
            ret_str.append(' range %d %d' % (port[0], port[1]))
          else:
            ret_str.append(' eq %d' % port[0])
          ret_str.append('exit\n')

    return '\n'.join(ret_str)


class PortMap:
  """Map port numbers to service names."""
  # Define port mappings common to all protocols
  _PORTS_TCP = {
      179: 'bgp',
      19: 'chargen',
      514: 'cmd',
      13: 'daytime',
      9: 'discard',
      53: 'domain',
      7: 'echo',
      512: 'exec',
      79: 'finger',
      21: 'ftp',
      20: 'ftp-data',
      70: 'gopher',
      443: 'https',
      113: 'ident',
      194: 'irc',
      543: 'klogin',
      544: 'kshell',
      389: 'ldap',
      636: 'ldaps',
      513: 'login',
      515: 'lpd',
      2049: 'nfs',
      119: 'nntp',
      496: 'pim-auto-rp',
      109: 'pop2',
      110: 'pop3',
      1723: 'pptp',
      25: 'smtp',
      22: 'ssh',
      111: 'sunrpc',
      49: 'tacacs',
      517: 'talk',
      23: 'telnet',
      540: 'uucp',
      43: 'whois',
      80: 'www',
  }
  _PORTS_UDP = {
      512: 'biff',
      68: 'bootpc',
      67: 'bootps',
      9: 'discard',
      195: 'dnsix',
      53: 'domain',
      7: 'echo',
      500: 'isakmp',
      434: 'mobile-ip',
      42: 'nameserver',
      138: 'netbios-dgm',
      137: 'netbios-ns',
      2049: 'nfs',
      123: 'ntp',
      496: 'pim-auto-rp',
      520: 'rip',
      161: 'snmp',
      162: 'snmptrap',
      111: 'sunrpc',
      514: 'syslog',
      49: 'tacacs',
      517: 'talk',
      69: 'tftp',
      37: 'time',
      513: 'who',
      177: 'xdmcp',
  }
  _TYPES_ICMP = {
      6: 'alternate-address',
      31: 'conversion-error',
      8: 'echo',
      0: 'echo-reply',
      16: 'information-reply',
      15: 'information-request',
      18: 'mask-reply',
      17: 'mask-request',
      32: 'mobile-redirect',
      12: 'parameter-problem',
      5: 'redirect',
      9: 'router-advertisement',
      10: 'router-solicitation',
      4: 'source-quench',
      11: 'time-exceeded',
      14: 'timestamp-reply',
      13: 'timestamp-request',
      30: 'traceroute',
      3: 'unreachable',
  }

  # Combine cisco-specific port mappings with common ones
  _CISCO_PORTS_TCP = {
      5190: 'aol',
      1494: 'citrix-ica',
      2748: 'ctiqbe',
      1720: 'h323',
      101: 'hostname',
      143: 'imap4',
      750: 'kerberos',
      1352: 'lotusnotes',
      139: 'netbios-ssn',
      5631: 'pcanywhere-data',
      1521: 'sqlnet',
  }
  _CISCO_PORTS_TCP.update(_PORTS_TCP)
  _CISCO_PORTS_UDP = {
      750: 'kerberos',
      5632: 'pcanywhere-status',
      1645: 'radius',
      1646: 'radius-acct',
      5510: 'secureid-udp',
  }
  _CISCO_PORTS_UDP.update(_PORTS_UDP)

  # Combine arista-specific port mappings with common ones
  _ARISTA_PORTS_TCP = {
      143: 'imap',
      88: 'kerberos',
  }
  _ARISTA_PORTS_TCP.update(_PORTS_TCP)
  _ARISTA_PORTS_UDP = {
      88: 'kerberos',
      1812: 'radius',
      1813: 'radius-acct',
  }
  _ARISTA_PORTS_UDP.update(_PORTS_UDP)

  # Full port map data structure
  _PORT_MAP = {
      'cisco': {
          'tcp': _CISCO_PORTS_TCP,
          'udp': _CISCO_PORTS_UDP,
          'icmp': _TYPES_ICMP
      },
      'arista': {
          'tcp': _ARISTA_PORTS_TCP,
          'udp': _ARISTA_PORTS_UDP,
          'icmp': _TYPES_ICMP
      }
  }

  @staticmethod
  def GetProtocol(port_num, proto, platform='cisco'):
    """Converts a port number to a name or returns the number.

    Args:
      port_num: integer representing the port number.
      proto: string representing proto (tcp, udp, etc).
      platform: string representing platform (cisco, arista)

    Returns:
      A name of the protocol or the port number that was provided.
    """
    try:
      port_map = PortMap._PORT_MAP[platform][proto]
      return port_map[port_num]
    except KeyError:
      return port_num


class Term(aclgenerator.Term):
  """A single ACL Term."""
  ALLOWED_PROTO_STRINGS = ['eigrp', 'gre', 'icmp', 'igmp', 'igrp', 'ip',
                           'ipinip', 'nos', 'pim', 'tcp', 'udp',
                           'sctp', 'ahp']

  IPV4_ADDRESS = Union[nacaddr.IPv4, ipaddress.IPv4Network]
  IPV6_ADDRESS = Union[nacaddr.IPv6, ipaddress.IPv6Network]

  def __init__(self, term, af=4, proto_int=True, enable_dsmo=False,
               term_remark=True, platform='cisco', verbose=True):
    super().__init__(term)
    self.term = term
    self.proto_int = proto_int
    self.options = []
    self.enable_dsmo = enable_dsmo
    self.term_remark = term_remark
    self.platform = platform
    self.verbose = verbose
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    if af == 4:
      self.text_af = 'inet'
    else:
      self.text_af = 'inet6'
    self.ALLOWED_PROTO_STRINGS.extend([self.PROTO_MAP.get(x)
                                       for x in self.ALWAYS_PROTO_NUM])

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self.platform not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self.platform in self.term.platform_exclude:
        return ''

    ret_str = ['\n']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(
          term=self.term.name,
          proto=', '.join(self.term.protocol),
          af=self.text_af))
      return ''
    if self.verbose:
      if self.term_remark:
        ret_str.append(' remark ' + self.term.name)
      if self.term.owner:
        self.term.comment.append('Owner: %s' % self.term.owner)
      for comment in self.term.comment:
        for line in comment.split('\n'):
          ret_str.append(' remark ' + str(line)[:100].rstrip())

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim[0] == self.platform:
          ret_str.append(str(next_verbatim[1]))
      return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      if self.af == 6:
        protocol = ['ipv6']
      elif self.platform == 'ciscoxr':
        protocol = ['ipv4']
      else:
        protocol = ['ip']
    elif self.term.protocol == ['hopopt']:
      protocol = ['hbh']
    elif self.proto_int:
      protocol = [proto if proto in self.ALLOWED_PROTO_STRINGS
                  else self.PROTO_MAP.get(proto)
                  for proto in self.term.protocol]
    else:
      protocol = self.term.protocol
    # Arista can not process acls with esp/ah, these must appear as integers.
    if self.platform == 'arista':
      if 'esp' in protocol:
        protocol = [x if x != 'esp' else '50' for x in protocol]
      if 'ah' in protocol:
        protocol = [x if x != 'ah' else '51' for x in protocol]

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', self.af)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.af)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
      if not source_address:
        logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                     direction='source',
                                                     af=self.text_af))
        return ''
      if self.enable_dsmo:
        source_address = summarizer.Summarize(source_address)
    else:
      # source address not set
      source_address = ['any']

    # destination address
    if self.term.destination_address:
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', self.af)
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', self.af)
      if destination_address_exclude:
        destination_address = nacaddr.ExcludeAddrs(
            destination_address,
            destination_address_exclude)
      if not destination_address:
        logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                     direction='destination',
                                                     af=self.text_af))
        return ''
      if self.enable_dsmo:
        destination_address = summarizer.Summarize(destination_address)
    else:
      # destination address not set
      destination_address = ['any']

    # options
    opts = [str(x) for x in self.term.option]
    if (self.PROTO_MAP['tcp'] in protocol or 'tcp' in protocol) and (
        'tcp-established' in opts or 'established' in opts
    ):
      if 'established' not in self.options:
        self.options.append('established')
    # Using both 'fragments' and 'is-fragment', ref Github Issue #187
    if ('ip' in protocol) and (
        ('fragments' in opts) or ('is-fragment' in opts)
    ):
      if 'fragments' not in self.options:
        self.options.append('fragments')
    # ACL-based Forwarding
    if (
        (self.platform == 'ciscoxr')
        and not self.term.action
        and self.term.next_ip
        and ('nexthop1' not in opts)
    ):
      if len(self.term.next_ip) > 1:
        raise CiscoNextIpError(
            'The following term has more than one next IP value: %s'
            % self.term.name
        )
      if not isinstance(self.term.next_ip[0], nacaddr.IPv4) and not isinstance(
          self.term.next_ip[0], nacaddr.IPv6
      ):
        raise CiscoNextIpError(
            'Next IP value must be an IP address. Invalid term: %s'
            % self.term.name
        )
      if self.term.next_ip[0].num_addresses > 1:
        raise CiscoNextIpError(
            'The following term has a subnet instead of a host: %s'
            % self.term.name
        )
      nexthop = self.term.next_ip[0].network_address
      nexthop_protocol = 'ipv4' if nexthop.version == 4 else 'ipv6'
      self.options.append('nexthop1 %s %s' % (nexthop_protocol, nexthop))
      action = _ACTION_TABLE.get('accept')

    if self.term.action:
      action = _ACTION_TABLE.get(str(self.term.action[0]))

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self._FixConsecutivePorts(self.term.source_port)

    if self.term.destination_port:
      destination_port = self._FixConsecutivePorts(self.term.destination_port)

    # logging
    if self.term.logging:
      self.options.append('log')

    # dscp; unlike srx, cisco only supports single, non-except values
    if self.term.dscp_match:
      if len(self.term.dscp_match) > 1:
        raise ExtendedACLTermError(
            'Extended ACLs cannot specify more than one dscp match value')
      else:
        self.options.append('dscp %s' % ' '.join(self.term.dscp_match))

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.af)
    icmp_codes = ['']
    if self.term.icmp_code:
      icmp_codes = self.term.icmp_code
    fixed_src_addresses = [self._GetIpString(x) for x in source_address]
    fixed_dst_addresses = [self._GetIpString(x) for x in destination_address]
    fixed_opts = {}
    for p in protocol:
      fixed_opts[p] = self._FixOptions(p, self.options)
    for saddr in fixed_src_addresses:
      for daddr in fixed_dst_addresses:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              opts = fixed_opts[proto]
              # cisconx uses icmp for both ipv4 and ipv6
              if self.platform == 'cisconx':
                if self.af == 6:
                  proto = 'icmp' if proto == 'icmpv6' else proto
              for icmp_type in icmp_types:
                for icmp_code in icmp_codes:
                  ret_str.extend(
                      self._TermletToStr(action, proto, saddr,
                                         self._FormatPort(sport, proto), daddr,
                                         self._FormatPort(dport, proto),
                                         icmp_type, icmp_code, opts))

    return '\n'.join(ret_str)

  def _GetIpString(self, addr):
    """Formats the address object for printing in the ACL.

    Args:
      addr: str or ipaddr, address
    Returns:
      An address string suitable for the ACL.
    """
    if isinstance(addr, nacaddr.IPv4) or isinstance(addr,
                                                    ipaddress.IPv4Network):
      addr = cast(self.IPV4_ADDRESS, addr)
      if addr.num_addresses > 1:
        if self.platform == 'arista':
          return addr.with_prefixlen
        return '%s %s' % (addr.network_address, addr.hostmask)
      return 'host %s' % (addr.network_address)
    if isinstance(addr, nacaddr.IPv6) or isinstance(addr,
                                                    ipaddress.IPv6Network):
      addr = cast(self.IPV6_ADDRESS, addr)
      if addr.num_addresses > 1:
        return addr.with_prefixlen
      return 'host %s' % (addr.network_address)
    # DSMO enabled
    if isinstance(addr, summarizer.DSMNet):
      return '%s %s' % summarizer.ToDottedQuad(addr, negate=True)
    return addr

  def _FormatPort(self, port, proto):
    """Returns a formatted port string for the range.

    Args:
      port: str list or none, the port range.
      proto: str representing proto (tcp, udp, etc).

    Returns:
      A string suitable for the ACL.
    """
    if not port:
      return ''
    port0 = port[0]
    port1 = port[1]
    if self.platform == 'arista':
      port0 = PortMap.GetProtocol(port0, proto, self.platform)
      port1 = PortMap.GetProtocol(port1, proto, self.platform)

    if port[0] != port[1]:
      return 'range %s %s' % (port0, port1)
    return 'eq %s' % (port0)

  def _FixOptions(self, proto, option):
    """Returns a set of options suitable for the given protocol.

    Fix done:
    - Filter out 'established' for UDP.
    - Filter out 'fragments' for TCP/UDP

    Args:
      proto: str or int, protocol
      option: list or none, optional, eg. 'logging' tokens.
    Returns:
      A list of options suitable for that protocol.
    """
    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if ((proto == self.PROTO_MAP['udp'] or proto == 'udp')
        and 'established' in sane_options):
      sane_options.remove('established')
    return sane_options

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport,
                    icmp_type, icmp_code, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str or int, protocol
      saddr: str, source address
      sport: str, the source port
      daddr: str, the destination address
      dport: str, the destination port
      icmp_type: icmp-type numeric specification (if any)
      icmp_code: icmp-code numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.

    Raises:
      UnsupportedCiscoAccessListError: When unknown icmp-types specified
    """
    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(icmp_type)
    icmp_code = str(icmp_code)
    all_elements = [action, str(proto), saddr, sport, daddr, dport, icmp_type,
                    icmp_code, ' '.join(option)]
    non_empty_elements = [x for x in all_elements if x]
    return [' ' + ' '.join(non_empty_elements)]

  def _FixConsecutivePorts(self, port_list):
    """Takes a list of tuples and expands the tuple if the range is two.

        http://www.cisco.com/warp/public/cc/pd/si/casi/ca6000/tech/65acl_wp.pdf

    Args:
      port_list: A list of tuples representing ports.

    Returns:
      list of tuples
    """
    temporary_port_list = []
    for low_port, high_port in port_list:
      if low_port == high_port - 1:
        temporary_port_list.append((low_port, low_port))
        temporary_port_list.append((high_port, high_port))
      else:
        temporary_port_list.append((low_port, high_port))
    return temporary_port_list


class ObjectGroupTerm(Term):
  """An individual term of an object-group'd acl.

  Object Group acls are very similar to extended acls in their
  syntax except they use a meta language with address/service
  definitions.

  eg:

    permit tcp first-term-source-address 179-179 ANY

  where first-term-source-address, ANY and 179-179 are defined elsewhere
  in the acl.
  """
  # Protocols should be emitted as integers rather than strings.
  _PROTO_INT = True

  def __init__(self, term, filter_name, af=4, platform='cisco', verbose=True):
    super().__init__(term, af=af)
    self.term = term
    self.filter_name = filter_name
    self.platform = platform
    self.verbose = verbose

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self.platform not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self.platform in self.term.platform_exclude:
        return ''

    source_address_set = set()
    destination_address_set = set()
    ret_str = ['\n']
    if self.verbose:
      ret_str.append(' remark %s' % self.term.name)
      comments = aclgenerator.WrapWords(self.term.comment,
                                        _COMMENT_MAX_WIDTH)
      if comments and comments[0]:
        for comment in comments:
          ret_str.append(' remark %s' % str(comment))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim[0] == self.platform:
          ret_str.append(str(next_verbatim[1]))
      return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      if self.af == 6:
        protocol = ['ipv6']
      elif self.platform == 'ciscoxr':
        protocol = ['ipv4']
      else:
        protocol = ['ip']

    else:
      protocol = [proto if proto in self.ALLOWED_PROTO_STRINGS
                  else self.PROTO_MAP.get(proto)
                  for proto in self.term.protocol]

    # addresses
    source_address = self.term.source_address
    if not self.term.source_address:
      source_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]
    source_address_set.add(source_address[0].parent_token)

    destination_address = self.term.destination_address
    if not self.term.destination_address:
      destination_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]
    destination_address_set.add(destination_address[0].parent_token)
    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port
    for saddr in source_address_set:
      for daddr in destination_address_set:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              ret_str.append(
                  self._TermletToStr(_ACTION_TABLE.get(str(
                      self.term.action[0])), proto, saddr, sport, daddr, dport))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport):  # pytype: disable=signature-mismatch  # overriding-parameter-count-checks
    """Output a portion of a cisco term/filter only, based on the 5-tuple."""
    # Empty addr/port destinations should emit 'any'
    if saddr and saddr != 'any':
      saddr = 'net-group %s' % saddr
    if daddr and daddr != 'any':
      daddr = 'net-group %s' % daddr
    # fix ports
    if sport:
      sport = ' port-group %d-%d' % (sport[0], sport[1])
    else:
      sport = ''
    if dport:
      dport = ' port-group %d-%d' % (dport[0], dport[1])
    else:
      dport = ''

    return (' %s %s %s%s %s%s' % (
        action, proto, saddr, sport, daddr, dport)).rstrip()


class Cisco(aclgenerator.ACLGenerator):
  """A cisco policy object."""

  _PLATFORM = 'cisco'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.acl'
  # Protocols should be emitted as numbers.
  _PROTO_INT = True
  _TERM_REMARK = True

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'address',
                         'restrict_address_family',
                         'dscp_match',
                         'icmp_code',
                         'logging',
                         'owner'}

    supported_sub_tokens.update({'option': {'established',
                                            'tcp-established',
                                            'is-fragment',
                                            'fragments'},
                                 # Warning, some of these are mapped
                                 # differently. See _ACTION_TABLE
                                 'action': {'accept', 'deny', 'reject', 'next',
                                            'reject-with-tcp-rst'}})
    return supported_tokens, supported_sub_tokens

  def _IsConfigureReplaceCompatible(self, filter_options):
    if filter_options is not None:
      if 'configure_replace_compatible' in filter_options:
        return True
    return False

  def _TranslatePolicy(self, pol, exp_info):
    self.cisco_policies = []
    current_date = datetime.datetime.now(datetime.timezone.utc).date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['extended', 'standard', 'object-group',
                    'object-group-inet6', 'inet6', 'mixed', 'enable_dsmo']

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      self.verbose = True
      if 'noverbose' in filter_options:
        filter_options.remove('noverbose')
        self.verbose = False

      self.remove_duplicate_network_objectgroups = False
      if 'remove_duplicate_network_objectgroups' in filter_options:
        filter_options.remove('remove_duplicate_network_objectgroups')
        self.remove_duplicate_network_objectgroups = True

      # extended is the most common filter type.
      filter_type = 'extended'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      # check if filter type is renderable
      if filter_type not in good_filters:
        raise UnsupportedCiscoAccessListError(
            'access list type %s not supported by %s (good types: %s)' % (
                filter_type, self._PLATFORM, str(good_filters)))

      if filter_type == 'object-group-inet6':
        obj_target = ObjectGroup(af=6)
      else:
        obj_target = ObjectGroup()

      filter_list = [filter_type]
      if filter_type == 'mixed':
        # Loop through filter and generate output for inet and inet6 in sequence
        filter_list = ['extended', 'inet6']

      for next_filter in filter_list:
        # Numeric access lists can be extended or standard, but have specific
        # known ranges.
        if next_filter == 'extended' and filter_name.isdigit():
          if int(filter_name) in list(range(1, 100)) + list(range(1300, 2000)):
            raise UnsupportedCiscoAccessListError(
                'Access lists between 1-99 and 1300-1999 are reserved for '
                'standard ACLs')
        if next_filter == 'standard' and filter_name.isdigit():
          if (int(filter_name) not in list(range(1, 100)) +
              list(range(1300, 2000))):
            raise UnsupportedCiscoAccessListError(
                'Standard access lists must be numeric in the range of 1-99'
                ' or 1300-1999.')

        term_dup_check = set()
        new_terms = []
        for term in terms:
          if term.name in term_dup_check:
            raise CiscoDuplicateTermError('You have a duplicate term: %s' %
                                          term.name)
          term_dup_check.add(term.name)

          term.name = self.FixTermLength(term.name)
          af = 'inet'
          if next_filter == 'inet6':
            af = 'inet6'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue

          # Ignore if the term is for a different AF
          if (
              term.restrict_address_family
              and term.restrict_address_family != af
          ):
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info(
                  'INFO: Term %s in policy %s expires in less than two weeks.',
                  term.name,
                  filter_name,
              )
            if term.expiration <= current_date:
              logging.warning(
                  'WARNING: Term %s in policy %s is expired and '
                  'will not be rendered.',
                  term.name,
                  filter_name,
              )
              continue

          # render terms based on filter type
          if next_filter == 'standard':
            # keep track of sequence numbers across terms
            new_terms.append(
                TermStandard(term, filter_name, self._PLATFORM, self.verbose)
            )
          elif next_filter == 'extended':
            enable_dsmo = (
                len(filter_options) > 2 and filter_options[2] == 'enable_dsmo'
            )
            new_terms.append(
                Term(
                    term,
                    proto_int=self._PROTO_INT,
                    enable_dsmo=enable_dsmo,
                    term_remark=self._TERM_REMARK,
                    platform=self._PLATFORM,
                    verbose=self.verbose,
                )
            )
          elif next_filter == 'object-group':
            if term.source_address:
              srcs = term.GetAddressOfVersion('source_address', 4)
              if not srcs:
                continue
            if term.destination_address:
              dsts = term.GetAddressOfVersion('destination_address', 4)
              if not dsts:
                continue
            obj_target.AddTerm(term)
            new_terms.append(
                self._GetObjectGroupTerm(
                    term, filter_name, verbose=self.verbose
                )
            )
          elif next_filter == 'object-group-inet6':
            if term.source_address:
              srcs = term.GetAddressOfVersion('source_address', 6)
              if not srcs:
                continue
            if term.destination_address:
              dsts = term.GetAddressOfVersion('destination_address', 6)
              if not dsts:
                continue
            obj_target.AddTerm(term)
            new_terms.append(self._GetObjectGroupTerm(term, filter_name, af=6,
                                                      verbose=self.verbose))
          elif next_filter == 'inet6':
            new_terms.append(
                Term(
                    term,
                    6,
                    proto_int=self._PROTO_INT,
                    platform=self._PLATFORM,
                    verbose=self.verbose,
                )
            )

        # cisco requires different name for the v4 and v6 acls
        if filter_type == 'mixed' and next_filter == 'inet6':
          filter_name = 'ipv6-%s' % filter_name
        self.cisco_policies.append((header, filter_name, [next_filter],
                                    new_terms, obj_target, filter_options)
        )

  def _GetObjectGroupTerm(self, term, filter_name, af=4, verbose=True):
    """Returns an ObjectGroupTerm object."""
    return ObjectGroupTerm(term, filter_name, af=af, verbose=verbose)

  def _remove_duplicate_objects(self, target):
    """Remove all duplicate object-groups and rename to the first group found.

    Args:
      target: A string to remove duplicate object-groups from.

    Returns:
      A string with duplicate object-groups removed.
    Example:
    Remove all duplicate object-group and rename to the first group found
    where the format looks like:
    object-group network ipv4 firstgroup
     10.1.1.0/8
    exit
    object-group network ipv4 secondgroup
     10.1.1.0/8
    exit
    ipv4 access-list myacl
     permit tcp net-group firstgroup net-group secondgroup port-group 443-443
    exit
    Result:
    object-group network ipv4 sa_myfirstgroup
     10.1.1.0/8
    exit
    ipv4 access-list myacl
     permit tcp net-group firstgroup net-group secondgroup port-group 443-443
    exit
    """
    for address_family in ['ipv4', 'ipv6']:
      duplicate_object_groups = self._get_duplicate_object_groups(
          target, address_family
      )
      target = self._remove_object_groups(
          target, duplicate_object_groups.keys(), address_family
      )
      target = self._replace_object_groups_references(
          target, duplicate_object_groups, address_family
      )
    return target

  def _get_duplicate_object_groups(self, text, address_family):
    """Parses the given text to extract all object-groups.

    Args:
      text: A multi-line string with multiple object-groups contained within it.
      address_family: A string "ipv4" or "ipv6" to remove object-groups of.

    Returns:
      A dictionary of any duplicate content object-groups with the key of the
      duplicate name and the value of the first occurrence found name.
    """

    object_groups = {}
    duplicate_object_groups = {}

    inside_networkobject = False
    object_group_name = ''
    object_group_content = []
    for line in text.splitlines():
      if line.startswith('object-group'):
        fields = line.split()
        if len(fields) == 4:
          object_group_type = fields[1]
          object_group_af = fields[2]
          object_group_name = fields[3]
          if (
              object_group_type == 'network'
              and object_group_af == address_family
          ):
            inside_networkobject = True
      elif line.startswith('exit') and inside_networkobject:
        inside_networkobject = False
        if '\n'.join(object_group_content) in object_groups.keys():
          duplicate_object_groups[object_group_name] = object_groups[
              '\n'.join(object_group_content)
          ]
        else:
          object_groups['\n'.join(object_group_content)] = object_group_name
        object_group_content = []
      else:
        if inside_networkobject:
          object_group_content.append(line)
    return duplicate_object_groups

  def _remove_object_groups(self, text, objgroups, address_family):
    """Parses the given text to remove all object-groups asked to be removed.

    Args:
      text: A multi-line string with multiple object-groups contained within it.
      objgroups: A set of object-groups to remove.
      address_family: A string "ipv4" or "ipv6" to remove object-groups of.

    Returns:
      The original text with the duplicate object-groups removed.
    """

    inside_networkobject = False
    skip_line = False
    return_lines = []
    for line in text.splitlines():
      if line.startswith('object-group'):
        fields = line.split()
        if len(fields) == 4:
          object_group_type = fields[1]
          object_group_af = fields[2]
          object_group_name = fields[3]
          if (
              object_group_type == 'network'
              and object_group_af == address_family
          ):
            inside_networkobject = True
            if object_group_name in objgroups:
              skip_line = True
          else:
            skip_line = False
        else:
          skip_line = False
      elif line.startswith('exit') and inside_networkobject:
        inside_networkobject = False
        if skip_line:
          skip_line = False
          continue
        skip_line = False
      if skip_line:
        continue
      return_lines.append(line)
    return '\n'.join(return_lines)

  def _replace_object_groups_references(
      self, text, objgroups, address_family
  ):
    """Parses the given text to replace all object-groups in an ACL based on a dictionary.

    Args:
      text: A multi-line string with ACLs contained within it.
      objgroups: A dict of object-groups to the key with the value of in
        references.
      address_family: A string "ipv4" or "ipv6" to remove object-groups of.

    Returns:
      The original text with the object-group references changed to those in the
      dictionary.
    """

    inside = ''
    return_lines = []
    for line in text.splitlines():
      if line.startswith('ip access-list extended ') or line.startswith(
          'ipv4 access-list '
      ):
        inside = 'ipv4'
      elif line.startswith('ipv6 access-list ') or line.startswith(
          'ipv6 access-list '
      ):
        inside = 'ipv6'
      elif line.startswith('exit'):
        inside = ''
      elif address_family == inside:
        fields = line.split()
        if len(fields) >= 2:
          for i in range(len(fields) - 1):
            if fields[i] == 'net-group':
              if fields[i + 1] in objgroups:
                fields[i + 1] = objgroups[fields[i + 1]]
          line = ' ' + ' '.join(fields)
      return_lines.append(line)
    return '\n'.join(return_lines)

  def _FilterCmd(self, filter_name, filter_type):
    """Returns the filter name command.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter

    Returns:
      string

    Raises:
      UnsupportedCiscoAccessListError: When unknown filter type is used.
    """
    if filter_type == 'standard':
      return 'ip access-list standard %s' % filter_name
    if filter_type == 'extended':
      return 'ip access-list extended %s' % filter_name
    if filter_type == 'object-group':
      return 'ip access-list extended %s' % filter_name
    if filter_type == 'inet6' or filter_type == 'object-group-inet6':
      return 'ipv6 access-list %s' % filter_name
    raise UnsupportedCiscoAccessListError(
        'access list type %s not supported by %s'
        % (filter_type, self._PLATFORM)
    )

  def _AppendTargetByFilterType(
      self, filter_name, filter_type, configure_replace_compatible):
    """Takes in the filter name and type and appends headers.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter
      configure_replace_compatible: Bool indicating if the resulting config
        strings should be compatible with the configure replace command.

    Returns:
      list of strings
    """
    if filter_type == 'standard' and filter_name.isdigit():
      return ['no access-list %s' % filter_name]

    target = []
    filter_cmd = self._FilterCmd(filter_name, filter_type)
    if not configure_replace_compatible:
      target.append('no %s' % filter_cmd)
    target.append(filter_cmd)
    return target

  def _RepositoryTagsHelper(self, target=None, filter_type='', filter_name=''):
    if target is None:
      target = []
    if filter_type == 'standard' and filter_name.isdigit():
      target.extend(aclgenerator.AddRepositoryTags(
          'access-list %s remark ' % filter_name, date=False, revision=False))
    else:
      target.extend(aclgenerator.AddRepositoryTags(
          ' remark ', date=False, revision=False))
    return target

  def __str__(self):
    target_header = []
    target = []
    # add the p4 tags
    target.extend(aclgenerator.AddRepositoryTags('! '))

    for (header, filter_name, filter_list, terms, obj_target, filter_options
        ) in self.cisco_policies:
      configure_replace_compatible = self._IsConfigureReplaceCompatible(
          filter_options)
      for filter_type in filter_list:
        target.extend(self._AppendTargetByFilterType(
            filter_name, filter_type, configure_replace_compatible))
        if filter_type == 'object-group' or filter_type == 'object-group-inet6':
          obj_target.AddName(filter_name)

        # Add the Perforce Id/Date tags, these must come after
        # remove/re-create of the filter, otherwise config mode doesn't
        # know where to place these remarks in the configuration.
        if self.verbose:
          target = self._RepositoryTagsHelper(target, filter_type, filter_name)

          # add a header comment if one exists

          for comment in aclgenerator.WrapWords(header.comment,
                                                _COMMENT_MAX_WIDTH):
            for line in comment.split('\n'):
              if (self._PLATFORM == 'cisco' and filter_type == 'standard' and
                  filter_name.isdigit()):
                target.append('access-list %s remark %s' % (filter_name, line))
              else:
                target.append(' remark %s' % line)

        # now add the terms
        for term in terms:
          term_str = str(term)
          if term_str:
            target.append(term_str)

      if obj_target.valid:
        target = [str(obj_target)] + target
      # ensure that the header is always first
      target = target_header + target
      if not configure_replace_compatible:
        target += ['', 'exit', '']
    if self.remove_duplicate_network_objectgroups:
      return self._remove_duplicate_objects('\n'.join(target))
    return '\n'.join(target)
