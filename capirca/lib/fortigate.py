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

"""Fortigate generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime

from capirca.lib import nacaddr
from absl import logging
from capirca.lib import aclgenerator

_ACTION_TABLE = {
  'accept': 'accept',
  'deny': 'deny',
  'reject': 'deny',
  'reject-with-tcp-rst': 'deny',  # tcp rst not supported
}


class UnsupportedFilterError(Exception):
  pass


class FortiGateValueError(Exception):
  pass


class FortiGateFindServiceError(Exception):
  pass


class FortiGateDuplicateTermError(Exception):
  pass


class FortigatePortMap(object):
  _PORTS_TCP = {
    179: 'BGP',
    53: 'DNS',
    7: 'PING',
    79: 'FINGER',
    21: 'FTP',
    70: 'GOPHER',
    443: 'HTTPS',
    194: 'IRC',
    2049: 'NFS',
    119: 'NNTP',
    110: 'POP3',
    1723: 'PPTP',
    25: 'SMTP',
    22: 'SSH',
    517: 'TALK',
    23: 'TELNET',
    540: 'UUCP',
    80: 'HTTP',
    993: 'IMAPS',
    3389: 'RDP',
    3306: 'MYSQL',
    1433: 'MS-SQL',
    1812: 'RADIUS',
    995: 'POP3S',
    465: 'SMTPS',
    389: 'LDAP',
    69: 'TFTP'

  }

  _PORTS_UDP = {
    53: 'DNS',
    7: 'PING',
    500: 'IKE',
    2049: 'NFS',
    123: 'NTP',
    520: 'RIP',
    161: 'SNMP',
    162: 'snmptrap',
    514: 'SYSLOG',
    517: 'TALK',
    69: 'TFTP',
    37: 'TIMESTAMP',
    1812: 'RADIUS',
    67: 'DHCP'

  }

  _PROTO_MAP = {
    'icmp': 'ALL_ICMP',
    'gre': 'GRE',
    'ip': 'ALL',
    'tcp': _PORTS_TCP,
    'udp': _PORTS_UDP
  }

  @staticmethod
  def GetProtocol(protocol, port=None):
    f_proto = FortigatePortMap._PROTO_MAP.get(protocol, None)
    if f_proto is None:
      raise FortiGateValueError('%r protocol is not supported by Fortigate, supported protocols = %r' % (
        protocol, FortigatePortMap._PROTO_MAP.keys()))

    if isinstance(f_proto, str):
      return f_proto
    elif port:
      return f_proto[port]

    else:
      raise FortiGateFindServiceError('failed to get service from %r protocol and %r port' % (protocol, port))


class Term(aclgenerator.Term):
  ALLOWED_PROTO_STRINGS = ['gre', 'icmp', 'ip', 'tcp', 'udp']
  COMMENT_MAX_WIDTH = 70

  FW_ADDRESSES = []
  FW_SERVICES = []

  _FW_DUP_CHECK = set()

  CURRENT_ID = 0

  def __init__(self, term):
    super(Term, self).__init__(term)
    self._term = term

    self.id = type(self).CURRENT_ID
    type(self).CURRENT_ID += 1

  @staticmethod
  def get_fw_addresses():
    Term.FW_ADDRESSES.extend([' ', 'end', ' '])
    return Term.FW_ADDRESSES

  @staticmethod
  def get_fw_services():
    Term.FW_SERVICES.extend([' ', 'end', ' '])
    return Term.FW_SERVICES

  @staticmethod
  def _get_addresses_name(addresses):
    v4_addresses = [x.with_prefixlen for x in addresses if
                    not isinstance(x, nacaddr.IPv6)]
    addresses = ' '.join(v4_addresses)
    return addresses or 'all'

  def _get_services_string(self, protocol, ports):

    services = []
    if protocol and not ports:
      services.append(FortigatePortMap.GetProtocol(protocol[0]))
    for port in ports:
      try:
        service = FortigatePortMap.GetProtocol(protocol[0], port[0])
      except KeyError:
        self._add_service_to_fw_services(protocol[0], port[0])
        service = str(port[0])
      services.append(service)

    return ' '.join(services) or 'ALL'

  def _add_address_to_fw_addresses(self, addr):
    if addr in type(self)._FW_DUP_CHECK:
      return
    type(self).FW_ADDRESSES.extend(['\tedit %s' % addr,
                                    '\t\tset subnet %s' % addr,
                                    '\tnext'])
    type(self)._FW_DUP_CHECK.add(addr)

  def _add_service_to_fw_services(self, protocol, service):
    if service in type(self)._FW_DUP_CHECK:
      return

    type(self).FW_SERVICES.extend(['\tedit %s' % service,
                                   '\t\tset protocol TCP/UDP',
                                   '\t\tset %s-portrange %s' % (protocol.lower(), service),
                                   '\tnext'])

    type(self)._FW_DUP_CHECK.add(service)

  def _generate_address_names(self, *addresses):
    for group in addresses:
      for addr in group:
        if addr and not isinstance(addr, nacaddr.IPv6):
          self._add_address_to_fw_addresses(addr.with_prefixlen)

  def __str__(self):
    lines = []

    self._generate_address_names(self._term.destination_address, self._term.source_address)
    # lines.extend(self.firewall_addresses)

    dest_addresses = self._get_addresses_name(self._term.destination_address)
    src_addresses = self._get_addresses_name(self._term.source_address)
    services = self._get_services_string(self._term.protocol, self._term.destination_port)

    lines.append('\t\tset comments %s' % self._term.name)
    lines.append('\t\tset srcintf %s' % (self._term.source_interface or 'any'))
    lines.append('\t\tset dstintf %s' % (self._term.destination_interface or 'any'))
    lines.append('\t\tset dstaddr %s' % dest_addresses)
    lines.append('\t\tset srcaddr %s' % src_addresses)
    lines.append('\t\tset action %s' % _ACTION_TABLE.get(self._term.action[0]))
    lines.append('\t\tset service %s' % services)
    lines.append('\t\tset schedule always')
    if self._term.logging:
      lines.append('\t\tset logtraffic all')

    return '\n'.join(lines)


class Fortigate(aclgenerator.ACLGenerator):
  """A cisco policy object."""

  _PLATFORM = 'fortigate'
  _DEFAULT_PROTOCOL = 'ALL'
  SUFFIX = '.fcl'
  # Protocols should be emitted as numbers.
  _PROTO_INT = True
  _TERM_REMARK = True

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(Fortigate, self)._BuildTokens()

    supported_tokens |= {'source_interface',
                         'destination_interface',
                         'logging'}

    supported_sub_tokens.update({'option': {'from_id'},
                                 # Warning, some of these are mapped
                                 # differently. See _ACTION_TABLE
                                 'action': {'accept', 'deny', 'reject',
                                            'reject-with-tcp-rst'}})
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.fortigate_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options) < 2 or filter_options[0] != "from-id"):
        raise UnsupportedFilterError(
          "Fortigate Firewall filter arguments must specify from_id")

      from_id = filter_options[1]
      Term.CURRENT_ID = int(from_id)

      self.verbose = True
      if 'noverbose' in filter_options:
        filter_options.remove('noverbose')
        self.verbose = False

      term_dup_check = set()

      for term in terms:
        filter_name = header.FilterName(self._PLATFORM)
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s is expired and '
                         'will not be rendered.', term.name, filter_name)
            continue
        if term.name in term_dup_check:
          raise FortiGateDuplicateTermError('You have a duplicate term: %s' %
                                            term.name)
        term_dup_check.add(term.name)

        term.name = self.FixTermLength(term.name)
        new_term = Term(term)

        self.fortigate_policies.append((header, term.name, new_term))

  def _GetTargetByPolicyID(self, id):
    return '\tedit %s' % id

  def __str__(self):
    start_addresses = ['config firewall address']
    start_services = ['config firewall service custom']
    start_policies = ['config firewall policy']
    end = ['end']
    target_addresses = []
    target_services = []
    target_policies = []

    for (header, filter_name, term) in self.fortigate_policies:
      target_policies.append(self._GetTargetByPolicyID(term.id))

      term_str = str(term)

      target_policies.append(term_str)

      target_policies += ['\tnext', '']
    target_addresses.extend(Term.get_fw_addresses())
    target_services.extend(Term.get_fw_services())

    fw_addresses = start_addresses + target_addresses
    fw_services = start_services + target_services

    target = fw_addresses + fw_services + start_policies + target_policies + end

    return '\n'.join(target)
