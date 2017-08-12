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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = ['pmoody@google.com (Peter Moody)',
              'watson@google.com (Tony Watson)']


import datetime
import re

from lib import aclgenerator
from lib import nacaddr
from lib import summarizer
import ipaddr
import logging


_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
}


# generic error class
class Error(Exception):
  """Generic error class."""


class UnsupportedCiscoAccessListError(Error):
  """Raised when we're give a non named access list."""


class StandardAclTermError(Error):
  """Raised when there is a problem in a standard access list."""


class ExtendedACLTermError(Error):
  """Raised when there is a problem in an extended access list."""


class TermStandard(object):
  """A single standard ACL Term."""
  def __init__(self, term, filter_name, platform='cisco'):
    self.term = term
    self.filter_name = filter_name
    self.platform = platform
    self.options = []
    self.logstring = ''
    self.dscpstring = ''
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
      logging.warn(
          'WARNING: Standard ACL logging is set in filter %s, term %s and '
          'may not implemented on all IOS versions', self.filter_name,
          self.term.name)
      self.logstring = ' log'
    if self.term.dscp_match:
      logging.warn(
          'WARNING: dscp-match is set in filter %s, term %s and may not be '
          'implemented on all IOS version', self.filter_name, self.term_name)
      self.dscpstring = ' dscp' + self.term_dscp_match

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
        if next_verbatim.value[0] == self.platform:
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    v4_addresses = [x for x in self.term.address if type(x) != nacaddr.IPv6]
    if self.filter_name.isdigit():
      ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                   self.term.name))

      comment_max_width = 70
      comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
      if comments and comments[0]:
        for comment in comments:
          ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                       comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append('access-list %s %s %s%s%s' % (self.filter_name,
                                                         action,
                                                         addr.ip,
                                                         self.logstring,
                                                         self.dscpstring))
          else:
            ret_str.append('access-list %s %s %s %s%s%s' % (self.filter_name,
                                                            action,
                                                            addr.network,
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
      ret_str.append(' remark ' + self.term.name)
      comment_max_width = 70
      comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
      if comments and comments[0]:
        for comment in comments:
          ret_str.append(' remark ' + str(comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append(' %s host %s%s%s' % (action,
                                                addr.ip,
                                                self.logstring,
                                                self.dscpstring))
          else:
            ret_str.append(' %s %s %s%s%s' % (action,
                                              addr.network,
                                              addr.hostmask,
                                              self.logstring,
                                              self.dscpstring))
      else:
        ret_str.append(' %s %s%s%s' % (action,
                                       'any',
                                       self.logstring,
                                       self.dscpstring))

    return '\n'.join(ret_str)


class ObjectGroup(object):
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

  for cat6k (catos), no ipv6 support

    object-group ip address first-address-token-name
      host-info 172.16.0.0
      172.20.0.0 255.255.0.0
      172.22.0.0 255.128.0.0
      host-info 172.24.0.0
      host-info 172.28.0.0
    exit

  for cat4k (iosxe), no port group support by capirca

    object-group network first-address-token-name
      host 172.16.0.0
      172.20.0.0 255.255.0.0
      172.22.0.0 255.128.0.0
      host 172.24.0.0
      host 172.28.0.0
    exit
  """

  def __init__(self, sub_platform=None):
    self.filter_name = ''
    self.terms = []
    self.sub_platform = sub_platform

  @property
  def valid(self):
    return bool(self.terms)

  def AddTerm(self, term):
    self.terms.append(term)

  def AddName(self, filter_name):
    self.filter_name = filter_name

  def GetAlternateNames(self, term, glb_table):
      """Resolves the conflicts in object-names after checking
      the global address object groups table.

      Args:
        term: object group term
      Returns:
        List of the alternate names to be used while
      rendering ObjectGroupTerm
      """
      dup_addr_type = ('source_address', 'destination_address')
      dup_addr_family = (4, 6)
      group_name_alt = {}

      for source_or_dest in dup_addr_type:
          for family in dup_addr_family:
              dup_addrs = term.GetAddressOfVersion(source_or_dest, family)
              if dup_addrs:
                  p_group_name = dup_addrs[0].parent_token
                  p_alt_index = 0
                  if p_group_name not in glb_table:
                      glb_table[p_group_name] = [dup_addrs]
                  else:
                      for g_addrs in glb_table[p_group_name]:
                          if dup_addrs == g_addrs:
                              break
                          else:
                              p_alt_index += 1
                      if p_alt_index == len(glb_table[p_group_name]):
                          glb_table[p_group_name].append(dup_addrs)
                  if p_alt_index > 0:
                      group_name_alt[source_or_dest] = '%s_%d' % (p_group_name,
                                                                  p_alt_index)
      return group_name_alt

  def __str__(self):
    def _GetObjectGroupHeader(sub_platform, group_type, family, group_name):
      if group_type == 'network':
        if not sub_platform:
          return 'object-group network ipv%d %s' % (
                  family, group_name)
        elif sub_platform == 'iosxe':
          return 'object-group network %s' % group_name
        elif sub_platform == 'catos':
          if family == 6:
            raise ExtendedACLTermError('CatOS platform does not support object groups'
                                       'with inet6 family')
          return 'object-group ip address %s' % group_name
      elif group_type == 'port':
        if not sub_platform:
          return 'object-group port %s' % group_name
        elif sub_platform == 'catos':
          return 'object-group ip port %s' % group_name

      return None

    def _GetObjectGroupAddrLine(sub_platform, addr):
      if not sub_platform:
        return ' %s/%s' % (addr.ip, addr.prefixlen)
      elif sub_platform == 'catos':
        if addr.numhosts > 1:
          return ' %s %s' % (addr.ip, addr.netmask)
        else:
          return ' host-info %s' % addr.ip
      elif sub_platform == 'iosxe':
        if addr.numhosts > 1:
          return ' %s %s' % (addr.ip, addr.netmask)
        else:
          return ' host %s' % addr.ip
      return None

    # netgroups will contain two-tuples of group name string and family int.
    netgroups = set()
    ports = set()
    ret_str_addrs = ['\n']
    ret_str_ports = ['\n']

    for obj_term in self.terms:
      # in current policy parsing logic, all tokens in src/dest fields are
      # combined into a single list of IP addresses. To name that list as
      # object group we depend on the parent_token of the first IP address of
      # the list. If src/dest is a combination of multiple tokens from
      # NETWORK.net, this logic of picking names could create naming conflicts.
      # To prevent conflicts, we create alternative names if there is conflict
      # e.g., parent token of an IP addresses already used for representing
      # another object group

      # Create network object-groups
      addr_type = ('source_address', 'destination_address')
      addr_family = (4, 6)
      term = obj_term.term
      term_addr_groups = obj_term.addr_groups


      for source_or_dest in addr_type:
        for family in addr_family:
          addrs = term.GetAddressOfVersion(source_or_dest, family)
          if addrs:
            # if we have an alternative name in global table use it
            # otherwise use the parent token to name object group
            net_def_name = term_addr_groups.get(str(source_or_dest),
                addrs[0].parent_token)

            # We have addresses for this family and have not already seen it.
            if (net_def_name, family) not in netgroups:
              netgroups.add((net_def_name, family))
              group_header_str = _GetObjectGroupHeader(self.sub_platform,
                  'network', family, net_def_name)
              # remove the old object group first
              ret_str_addrs.append("no " + group_header_str)
              ret_str_addrs.append(group_header_str)
              for addr in addrs:
                ret_str_addrs.append(_GetObjectGroupAddrLine(self.sub_platform,
                    addr))
              ret_str_addrs.append('exit\n')

      # Create port object-groups
      for port in term.source_port + term.destination_port:
        if not port:
          continue
        port_key = '%s-%s' % (port[0], port[1])
        if port_key not in ports:
          group_header_str = _GetObjectGroupHeader(self.sub_platform, 'port',
              None, port_key)
          if group_header_str:
            ports.add(port_key)
            ret_str_ports.append("no " + group_header_str)
            ret_str_ports.append(group_header_str)
            if port[0] != port[1]:
              ret_str_ports.append(' range %d %d' % (port[0], port[1]))
            else:
              ret_str_ports.append(' eq %d' % port[0])
            ret_str_ports.append('exit\n')

      ret_str_addrs.extend(ret_str_ports)

    return '\n'.join(ret_str_addrs)


class Term(aclgenerator.Term):
  """A single ACL Term."""
  ALLOWED_PROTO_STRINGS = ['eigrp', 'gre', 'icmp', 'igmp', 'igrp', 'ip',
                           'ipinip', 'nos', 'pim', 'tcp', 'udp',
                           'sctp', 'ahp']

  def __init__(self, term, af=4, proto_int=True, enable_dsmo=False,
               term_remark=True, platform='cisco'):
    super(Term, self).__init__(term)
    self.term = term
    self.proto_int = proto_int
    self.options = []
    self.enable_dsmo = enable_dsmo
    self.term_remark = term_remark
    self.platform = platform
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    if af == 4:
      self.text_af = 'inet'
    else:
      self.text_af = 'inet6'

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
      logging.debug(self.NO_AF_LOG_PROTO.substitute(term=self.term.name,
                                                    proto=self.term.protocol,
                                                    af=self.text_af))
      return ''

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
        if next_verbatim.value[0] == self.platform:
          ret_str.append(str(next_verbatim.value[1]))
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
    if ((self.PROTO_MAP['tcp'] in protocol or 'tcp' in protocol)
        and ('tcp-established' in opts or 'established' in opts)):
      if 'established' not in self.options:
        self.options.append('established')

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
        raise ExtendedAclTermError(
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
              for icmp_type in icmp_types:
                for icmp_code in icmp_codes:
                  ret_str.extend(self._TermletToStr(
                      _ACTION_TABLE.get(str(self.term.action[0])),
                      proto,
                      saddr,
                      self._FormatPort(sport, proto),
                      daddr,
                      self._FormatPort(dport, proto),
                      icmp_type,
                      icmp_code,
                      opts))

    return '\n'.join(ret_str)

  def _GetIpString(self, addr):
    """Formats the address object for printing in the ACL.

    Args:
      addr: str or ipaddr, address
    Returns:
      An address string suitable for the ACL.
    """
    if type(addr) is nacaddr.IPv4 or type(addr) is ipaddr.IPv4Network:
      if addr.numhosts > 1:
        if self.platform == 'arista':
          return addr.with_prefixlen
        return '%s %s' % (addr.ip, addr.hostmask)
      return 'host %s' % (addr.ip)
    if type(addr) is nacaddr.IPv6 or type(addr) is ipaddr.IPv6Network:
      if addr.numhosts > 1:
        return addr.with_prefixlen
      return 'host %s' % (addr.ip)
    # DSMO enabled
    if type(addr) is tuple:
      return '%s %s' % summarizer.ToDottedQuad(addr, negate=True)
    return addr

  def _FormatPort(self, port, proto):
    """Returns a formatted port string for the range.

    Args:
      port: str list or none, the port range
    Returns:
      A string suitable for the ACL.
    """
    if not port:
      return ''

    port0 = port[0]
    port1 = port[1]
    if self.platform == 'arista':
      port0 = self._TermPortToProtocol(port0, proto)
      port1 = self._TermPortToProtocol(port1, proto)

    if port[0] != port[1]:
      return 'range %s %s' % (port0, port1)
    return 'eq %s' % (port0)

  def _TermPortToProtocol(self, portNumber, proto):
    _PORTS_TCP = {
        5190: 'aol',
        179: 'bgp',
        19: 'chargen',
        1494: 'citrix-ica',
        514: 'cmd',
        2748: 'ctiqbe',
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
        1720: 'h323',
        101: 'hostname',
        113: 'ident',
        143: 'imap4',
        194: 'irc',
        750: 'kerberos',
        543: 'klogin',
        544: 'kshell',
        389: 'ldap',
        636: 'ldaps',
        515: 'lpd',
        513: 'login',
        1352: 'lotusnotes',
        139: 'netbios-ssn',
        2049: 'nfs',
        119: 'nntp',
        5631: 'pcanywhere-data',
        496: 'pim-auto-rp',
        109: 'pop2',
        110: 'pop3',
        1723: 'pptp',
        25: 'smtp',
        1521: 'sqlnet',
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
        53: 'domain',
        195: 'dnsix',
        7: 'echo',
        500: 'isakmp',
        750: 'kerberos',
        434: 'mobile-ip',
        42: 'nameserver',
        137: 'netbios-ns',
        138: 'netbios-dgm',
        2049: 'nfs',
        123: 'ntp',
        5632: 'pcanywhere-status',
        496: 'pim-auto-rp',
        1645: 'radius',
        1646: 'radius-acct',
        520: 'rip',
        5510: 'secureid-udp',
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

    if proto == 'tcp':
      if portNumber in _PORTS_TCP:
        return _PORTS_TCP[portNumber]
    elif proto == 'udp':
      if portNumber in _PORTS_UDP:
        return _PORTS_UDP[portNumber]
    elif proto == 'icmp':
      if portNumber in _TYPES_ICMP:
        return _TYPES_ICMP[portNumber]
    return portNumber

  def _FixOptions(self, proto, option):
    """Returns a set of options suitable for the given protocol

    In practice this is only used to filter out 'established' for UDP.

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

  for cat6k (catos):

    permit tcp any addrgroup <object-group-name> any
    permit tcp any any portgroup <object-group-name>

  for cat4k (iosxe):

    permit tcp object-group <object-group-name> any
  """
  # Protocols should be emitted as integers rather than strings.
  _PROTO_INT = True

  def __init__(self, term, filter_name, platform='cisco', sub_platform=None,
               af=4, addr_groups={}):
    super(ObjectGroupTerm, self).__init__(term)
    self.term = term
    self.filter_name = filter_name
    self.platform = platform
    self.sub_platform = sub_platform
    self.af = af
    self.addr_groups = addr_groups

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
    ret_str.append(' remark %s' % self.term.name)
    comment_max_width = 70
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      for comment in comments:
        ret_str.append(' remark %s' % str(comment))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == self._PLATFORM:
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      protocol = ['ip']

    else:
      protocol = [proto if proto in self.ALLOWED_PROTO_STRINGS
                  else self.PROTO_MAP.get(proto)
                  for proto in self.term.protocol]

    # addresses
    source_address = self.term.source_address
    if not self.term.source_address:
      source_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]

    # get the summarized object group name from addr_groups to prevent
    # naming conflicts else use the parent token from ip address
    src_group_name = self.addr_groups.get('source_address',
                                          source_address[0].parent_token)
    source_address_set.add(src_group_name)

    destination_address = self.term.destination_address
    if not self.term.destination_address:
      destination_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]

    # get the summarized object group name from addr_groups to prevent
    # naming conflicts else use the parent token from ip address
    dest_group_name = self.addr_groups.get('destination_address',
                                           destination_address[0].parent_token)
    destination_address_set.add(dest_group_name)

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    if self.term.logging:
      self.term.option.append('log')

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol,
                                           self.af)
    fixed_opts = {}
    for p in protocol:
      fixed_opts[p] = self._FixOptions(p, self.term.option)

    icmp_codes = ['']
    if self.term.icmp_code:
      icmp_codes = self.term.icmp_code

    for saddr in source_address_set:
      for daddr in destination_address_set:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              opts = fixed_opts[proto]
              for icmp_type in icmp_types:
                for icmp_code in icmp_codes:
                  ret_str.append(
                    self._TermletToStr(
                        _ACTION_TABLE.get(str(self.term.action[0])),
                        proto,
                        saddr,
                        sport,
                        daddr,
                        dport,
                        icmp_type,
                        icmp_code,
                        opts)
                  )
    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport,
                    icmp_type, icmp_code, option):
    """Output a portion of a cisco term/filter only, based on the 5-tuple."""
    net_group_pre = 'net-group'
    if self.sub_platform == 'catos':
      net_group_pre = 'addrgroup'
    elif self.sub_platform == 'iosxe':
      net_group_pre = 'object-group'

    # Empty addr/port destinations should emit 'any'
    if saddr and saddr != 'any':
      saddr = '%s %s' % (net_group_pre, saddr)
    if daddr and daddr != 'any':
      daddr = '%s %s' % (net_group_pre, daddr)

    port_group_pre = 'port-group'
    if self.sub_platform == 'catos':
      port_group_pre = 'portgroup'

    # fix ports
    if sport:
      if self.sub_platform != 'iosxe':
        sport = '%s %d-%d' % (port_group_pre, sport[0], sport[1])
      else:
        if sport[0] != sport[1]:
          sport = 'range %d %d' % (sport[0], sport[1])
        else:
          sport = 'eq %d' % sport[0]
    else:
      sport = ''
    if dport:
      if self.sub_platform != 'iosxe':
        dport = '%s %d-%d' % (port_group_pre, dport[0], dport[1])
      else:
        if dport[0] != dport[1]:
          dport = 'range %d %d' % (dport[0], dport[1])
        else:
          dport = 'eq %d' % dport[0]
    else:
      dport = ''

    # icmpv6 is not a valid keyword for ios/nxos
    if proto == 'icmpv6':
      proto = 'icmp'

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(icmp_type)
    icmp_code = str(icmp_code)
    all_elements = [action, str(proto), saddr, sport, daddr, dport, icmp_type,
                    icmp_code,
                    ' '.join(option)]
    non_empty_elements = [x for x in all_elements if x]
    return ' ' + ' '.join(non_empty_elements)



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
    supported_tokens, supported_sub_tokens = super(Cisco, self)._BuildTokens()

    supported_tokens |= {'address',
                         'dscp_match',
                         'icmp_code',
                         'logging',
                         'owner'}

    supported_sub_tokens.update({'option': {'established',
                                            'tcp-established'},
                                 # Warning, some of these are mapped
                                 # differently. See _ACTION_TABLE
                                 'action': {'accept', 'deny', 'reject', 'next',
                                            'reject-with-tcp-rst'}})
    return supported_tokens, supported_sub_tokens

  def _GetSubPlatform(self, filter_options):
    if 'iosxe' in filter_options:
      return 'iosxe'
    elif 'catos' in filter_options:
      return 'catos'
    return None

  def _TranslatePolicy(self, pol, exp_info):
    self.object_table = {}

    self.cisco_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['extended', 'standard', 'object-group', 'inet6',
                    'mixed']

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      sub_platform = self._GetSubPlatform(filter_options)
      # assumption: is only one subplatform type ACL in the policy file
      self.sub_platform = sub_platform
      obj_target = ObjectGroup(sub_platform=sub_platform)

      # extended is the most common filter type.
      filter_type = 'extended'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      # check if filter type is renderable
      if filter_type not in good_filters:
        raise UnsupportedCiscoAccessListError(
            'access list type %s not supported by %s (good types: %s)' % (
                filter_type, self._PLATFORM, str(good_filters)))

      filter_list = [filter_type]
      if filter_type == 'mixed':
        # Loop through filter and generate output for inet and inet6 in sequence
        filter_list = ['extended', 'inet6']

      for next_filter in filter_list:
        # Numeric access lists can be extended or standard, but have specific
        # known ranges.
        if next_filter == 'extended' and filter_name.isdigit():
          if int(filter_name) in range(1, 100) + range(1300, 2000):
            raise UnsupportedCiscoAccessListError(
                'Access lists between 1-99 and 1300-1999 are reserved for '
                'standard ACLs')
        if next_filter == 'standard' and filter_name.isdigit():
          if int(filter_name) not in range(1, 100) + range(1300, 2000):
            raise UnsupportedCiscoAccessListError(
                'Standard access lists must be numeric in the range of 1-99'
                ' or 1300-1999.')

        new_terms = []
        for term in terms:
          term.name = self.FixTermLength(term.name)
          af = 'inet'
          if next_filter == 'inet6':
            af = 'inet6'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info('INFO: Term %s in policy %s expires '
                           'in less than two weeks.', term.name, filter_name)
            if term.expiration <= current_date:
              logging.warn('WARNING: Term %s in policy %s is expired and '
                           'will not be rendered.', term.name, filter_name)
              continue

          # render terms based on filter type
          if next_filter == 'standard':
            # keep track of sequence numbers across terms
            new_terms.append(TermStandard(term, filter_name, self._PLATFORM))
          elif next_filter == 'extended':
            enable_dsmo = (len(filter_options) > 2 and
                           filter_options[2] == 'enable_dsmo')
            new_terms.append(
                Term(term, proto_int=self._PROTO_INT, enable_dsmo=enable_dsmo,
                     term_remark=self._TERM_REMARK, platform=self._PLATFORM))
          elif next_filter == 'object-group':
            group_name_alt = obj_target.GetAlternateNames(term,
                                                          self.object_table)
            obj_group_term = ObjectGroupTerm(term, filter_name,
                                             sub_platform=sub_platform,
                                             af=(4 if af == 'inet' else 6),
                                             addr_groups=group_name_alt)
            obj_target.AddTerm(obj_group_term)
            self._SetObjectGroupProtos(ObjectGroupTerm)
            new_terms.append(obj_group_term)
          elif next_filter == 'inet6':
            new_terms.append(Term(term, 6, proto_int=self._PROTO_INT))

        # cisco requires different name for the v4 and v6 acls
        if filter_type == 'mixed' and next_filter == 'inet6':
          filter_name = 'ipv6-%s' % filter_name
        self.cisco_policies.append((header, filter_name, [next_filter],
                                    new_terms, obj_target))

  def _SetObjectGroupProtos(self, object_group_term):
    pass

  def _AppendTargetByFilterType(self, filter_name, filter_type):
    """Takes in the filter name and type and appends headers.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter

    Returns:
      list of strings

    Raises:
      UnsupportedCiscoAccessListError: When unknown filter type is used.
    """
    target = []
    if filter_type == 'standard':
      if filter_name.isdigit():
        target.append('no access-list %s' % filter_name)
      else:
        target.append('no ip access-list standard %s' % filter_name)
        target.append('ip access-list standard %s' % filter_name)
    elif filter_type == 'extended':
      target.append('no ip access-list extended %s' % filter_name)
      target.append('ip access-list extended %s' % filter_name)
    elif filter_type == 'object-group':
      target.append('no ip access-list extended %s' % filter_name)
      target.append('ip access-list extended %s' % filter_name)
    elif filter_type == 'inet6':
      target.append('no ipv6 access-list %s' % filter_name)
      target.append('ipv6 access-list %s' % filter_name)
    else:
      raise UnsupportedCiscoAccessListError(
          'access list type %s not supported by %s' % (
              filter_type, self._PLATFORM))
    return target

  def __str__(self):
    object_group_summary = ObjectGroup(sub_platform=self.sub_platform)
    target_header = []
    target = []
    # add the p4 tags
    target.extend(aclgenerator.AddRepositoryTags('! '))

    for (header, filter_name, filter_list, terms, obj_target
        ) in self.cisco_policies:
      for filter_type in filter_list:
        target.extend(self._AppendTargetByFilterType(filter_name, filter_type))
        if filter_type == 'object-group':
          obj_target.AddName(filter_name)

        # Add the Perforce Id/Date tags, these must come after
        # remove/re-create of the filter, otherwise config mode doesn't
        # know where to place these remarks in the configuration.
        if filter_type == 'standard' and filter_name.isdigit():
          target.extend(
              aclgenerator.AddRepositoryTags(
                  'access-list %s remark ' % filter_name,
                  date=False, revision=False))
        else:
          target.extend(aclgenerator.AddRepositoryTags(
              ' remark ', date=False, revision=False))

        # add a header comment if one exists
        for comment in header.comment:
          for line in comment.split('\n'):
            target.append(' remark %s' % line)

        # now add the terms
        for term in terms:
          term_str = str(term)
          if term_str:
            target.append(term_str)

        if obj_target.valid:
          for oterm in obj_target.terms:
            object_group_summary.AddTerm(oterm)

      # ensure that the header is always first
      target = target_header + target
      target += ['', 'exit', '']

    if object_group_summary.valid:
      target = [str(object_group_summary)] + target

    return '\n'.join(target)
