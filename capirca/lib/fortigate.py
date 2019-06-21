# Copyright 2019 Google Inc. All Rights Reserved.
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
import six

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr


_ACTION_TABLE = {
  'accept': 'accept',
  'deny': 'deny',
  'reject': 'deny',
  'reject-with-tcp-rst': 'deny',  # tcp rst not supported
}


class Error(Exception):
  pass


class FilterError(Error):
  pass


class FortiGateValueError(Error):
  pass


class FortiGateFindServiceError(Error):
  pass


class FortiGateDuplicateTermError(Error):
  pass


class FortiGatePortDoesNotExist(Error):
  pass


class FortigatePortMap(object):
  """Map port numbers to service names"""
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
    """
    Converts a port number to a service name.
    :param protocol: string representing protocol (tcp, udp, etc).
    :param port: integer representing the port number.
    :return: the service name of provided port-protocol
    """
    f_proto = FortigatePortMap._PROTO_MAP.get(protocol, None)
    if f_proto is None:
      raise FortiGateValueError(
        '%r protocol is not supported by Fortigate, supported protocols = %r' % (
          protocol, FortigatePortMap._PROTO_MAP.keys()
        )
      )

    if isinstance(f_proto, six.string_types):
      return f_proto
    elif port:
      try:
        return f_proto[port]
      except KeyError:
        raise FortiGatePortDoesNotExist
    else:
      raise FortiGateFindServiceError(
        'failed to get service from %r protocol and %r port' % (protocol, port)
      )


class ObjectsContainer:
  """a Container that holds service and network objects"""

  def __init__(self):
    self._FW_ADDRESSES = []
    self._FW_SERVICES = []

    self._FW_DUP_CHECK = set()

  def get_fw_addresses(self):
    """return the collected addresses"""
    self._FW_ADDRESSES.extend([' ', 'end', ' '])
    return self._FW_ADDRESSES

  def get_fw_services(self):
    """return the collected services"""
    self._FW_SERVICES.extend([' ', 'end', ' '])
    return self._FW_SERVICES

  def _add_address_to_fw_addresses(self, addr):
    """add address to address store"""
    if addr in self._FW_DUP_CHECK:
      return
    self._FW_ADDRESSES.extend(['\tedit %s' % addr,
                               '\t\tset subnet %s' % addr,
                               '\tnext'])
    self._FW_DUP_CHECK.add(addr)

  def _add_service_to_fw_services(self, protocol, service):
    """add service to services store"""
    if service in self._FW_DUP_CHECK:
      return

    self._FW_SERVICES.extend(
      ['\tedit %s' % service,
       '\t\tset protocol TCP/UDP',
       '\t\tset %s-portrange %s' % (protocol.lower(), service),
       '\tnext']
    )

    self._FW_DUP_CHECK.add(service)


class Term(aclgenerator.Term):
  """Single Firewall Policy"""
  ALLOWED_PROTO_STRINGS = ['gre', 'icmp', 'ip', 'tcp', 'udp']
  COMMENT_MAX_WIDTH = 70

  CURRENT_ID = 0

  def __init__(self, term, object_container):
    super(Term, self).__init__(term)
    self._term = term
    self._obj_container = object_container

    self.id_ = type(self).CURRENT_ID
    type(self).CURRENT_ID += 1

  @staticmethod
  def _get_addresses_name(addresses):
    """return the addresses or 'all' if no addresses specified"""
    v4_addresses = [x.with_prefixlen for x in addresses if
                    not isinstance(x, nacaddr.IPv6)]
    addresses = ' '.join(v4_addresses)
    return addresses or 'all'

  @staticmethod
  def clean_ports(src_ports, dest_ports):
    """return a set() of src and dest ports"""
    all_ports = []
    if src_ports:
      all_ports += src_ports
    if dest_ports:
      all_ports += dest_ports
    return set(all_ports)

  def _get_services_string(self, protocol, ports):
    """
    get the service name if exist, if not create a service object and return the name
    :param protocol: list of protocols
    :param ports: list of ports
    :return:
    """

    services = []
    if protocol and not ports:
      services.append(FortigatePortMap.GetProtocol(protocol[0]))
    for port in ports:
      try:
        service = FortigatePortMap.GetProtocol(protocol[0], port[0])
      except FortiGatePortDoesNotExist:
        self._obj_container._add_service_to_fw_services(protocol[0], port[0])
        service = str(port[0])
      services.append(service)

    return ' '.join(services) or 'ALL'

  def _generate_address_names(self, *addresses):
    """this will generate the addresses names (object-network names)"""
    for group in addresses:
      for addr in group:
        if addr and not isinstance(addr, nacaddr.IPv6):
          self._obj_container._add_address_to_fw_addresses(addr.with_prefixlen)

  def __str__(self):
    lines = []

    self._generate_address_names(self._term.destination_address,
                                 self._term.source_address)

    dest_addresses = self._get_addresses_name(self._term.destination_address)
    src_addresses = self._get_addresses_name(self._term.source_address)
    all_ports = self.clean_ports(self._term.source_port, self._term.destination_port)

    services = self._get_services_string(self._term.protocol,
                                         all_ports)

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
  _TERM_MAX_LENGTH = 1023

  def __init__(self, *args, **kwargs):
    self._obj_container = ObjectsContainer()
    super(Fortigate, self).__init__(*args, **kwargs)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(Fortigate,
                                                   self)._BuildTokens()

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
    """Translate Capirca pol to fortigate pol"""
    self.fortigate_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options) < 2 or filter_options[0] != 'from-id'):
        raise FilterError(
          'Fortigate Firewall filter arguments must specify from_id')

      from_id = filter_options[1]
      Term.CURRENT_ID = int(from_id)

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

        new_term = Term(term, self._obj_container)

        self.fortigate_policies.append((header, term.name, new_term))

  def _GetTargetByPolicyID(self, id_):
    return '\tedit %s' % id_

  def __str__(self):
    start_addresses = ['config firewall address']
    start_services = ['config firewall service custom']
    start_policies = ['config firewall policy']
    end = ['end']
    target_addresses = []
    target_services = []
    target_policies = []

    for (_, _, term) in self.fortigate_policies:
      target_policies.append(self._GetTargetByPolicyID(term.id_))

      term_str = str(term)

      target_policies.append(term_str)

      target_policies += ['\tnext', '']
    target_addresses.extend(self._obj_container.get_fw_addresses())
    target_services.extend(self._obj_container.get_fw_services())

    fw_addresses = start_addresses + target_addresses
    fw_services = start_services + target_services

    target = fw_addresses + fw_services + start_policies + target_policies + end

    return '\n'.join(target)
