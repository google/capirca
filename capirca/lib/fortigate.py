# Copyright 2019 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Version 1.1.14

"""Fortigate generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
from absl import logging
import six

from capirca.lib import aclgenerator
from capirca.lib import nacaddr

_ACTION_TABLE = {
    'accept': 'accept',
    'deny': 'deny',
    'next': 'next',
    'reject': 'reject',
    'reject-with-tcp-rst': 'reject',  # set deny-tcp-with-icmp enable
}
_SP = '    '
_DEFAULT_COMMENT = ''
_SUPPORT_VERBATIM_TERM = False
_COMMENT_MAX_LENGTH = 1024


class Error(Exception):
  """Generic error class."""


class FilterError(Error):
  """Generic pol Filter class."""


class FortiGateValueError(Error):
  """Raised when invalid values provided."""


class FortiGateFindServiceError(Error):
  """Raised when unable to get the service name."""


class FortiGateDuplicateTermError(Error):
  """Raised when duplicate term found."""


class FortiGatePortDoesNotExistError(Error):
  """Raised when port is not found in ports list."""


class FortiGateScheduleDateError(Error):
  """Raised expiration date is invalid."""


class FortigatePortMap():
  """Map port numbers to service names."""
  _PORTS_TCP = {
      '179': 'BGP',
      '53': 'DNS',
      '7': 'PING',
      '79': 'FINGER',
      '21': 'FTP',
      '70': 'GOPHER',
      '443': 'HTTPS',
      '194': 'IRC',
      '2049': 'NFS',
      '119': 'NNTP',
      '110': 'POP3',
      '1723': 'PPTP',
      '25': 'SMTP',
      '22': 'SSH',
      '517': 'TALK',
      '23': 'TELNET',
      '540': 'UUCP',
      '80': 'HTTP',
      '993': 'IMAPS',
      '3389': 'RDP',
      '3306': 'MYSQL',
      '1433': 'MS-SQL',
      '1812': 'RADIUS',
      '995': 'POP3S',
      '465': 'SMTPS',
      '389': 'LDAP',
      '69': 'TFTP',
      'all': 'ALL_TCP'
  }
  _PORTS_UDP = {
      '53': 'DNS',
      '7': 'PING',
      '500': 'IKE',
      '2049': 'NFS',
      '123': 'NTP',
      '520': 'RIP',
      '161': 'SNMP',
      '162': 'snmptrap',
      '514': 'SYSLOG',
      '517': 'TALK',
      '69': 'TFTP',
      '37': 'TIMESTAMP',
      '1812': 'RADIUS',
      '67': 'DHCP',
      'all': 'ALL_UDP'
  }
  _PORTS_SCTP = {
      #'53': 'DNS',
      #'7': 'PING',
      'all': 'ALL_SCTP'
  }
  _PROTO_MAP = {
      'icmp': 'ALL_ICMP',
      'icmpv6': 'ALL_ICMP6',
      #'gre': 'GRE',
      #'ip': 'ALL',
      'tcp': _PORTS_TCP,
      'udp': _PORTS_UDP,
      'sctp': _PORTS_SCTP
  }

  @staticmethod
  def get_protocol(protocol, port=None):
    """Converts a port number to a service name.

  Args:
    protocol: string representing protocol (tcp, udp, etc)
    port: integer representing the port number

  Returns:
    string

  Raises:
    FortiGateValueError: When unsupported protocol is used.
    FortiGatePortDoesNotExistError: if the port does not exist.
    FortiGateFindServiceError: when unable to find the requested service.
  """
    f_proto = FortigatePortMap._PROTO_MAP.get(protocol, None)
    if f_proto is None:
      raise FortiGateValueError(
          f"{protocol} protocol is unsupported, supported protocols = {
            list(FortigatePortMap._PROTO_MAP.keys())}")

    if isinstance(f_proto, six.string_types):
      return f_proto
    if port:
      try:
        return f_proto[port]
      except KeyError as exc:
        raise FortiGatePortDoesNotExistError(f"Port {exc} does not exist") from exc
    else:
      raise FortiGateFindServiceError(
          f'service not found from {protocol} protocol and {port} port')


class ObjectsContainer():
  """A Container that holds service and network objects."""

  def __init__(self):
    self.verbose = True
    self._sys_settings = set()
    self._dict_addresses = set()
    self._dict_addrgrps = {}
    self._dict_services = {}
    self._dict_svcgrps = {}
    self._dict_schedules = {}

  def get_sys_settings(self):
    """Returns the collected addresses.

    """
    settings = []
    for setting in self._sys_settings:
      settings += [_SP + setting]

    return settings

  def get_fw_addresses(self, ip_v=4):
    """
    Returns the collected firewall addresses.

    Args:
        ip_v: an integer. version 4 or 6.

    Returns: a list. contains address objects.

    """
    addresses = []
    addresses_v = []
    for addr in self._dict_addresses:
      if ip_v == 4 and not isinstance(addr, nacaddr.IPv6):
        addresses_v += [addr]
      if ip_v == 6 and isinstance(addr, nacaddr.IPv6):
        addresses_v += [addr]

    for addr in sorted(addresses_v):
      addresses.extend(self.get_fw_address_obj(addr, self.verbose))

    return addresses

  def get_fw_address_obj(self, addr, verbose=True):
    """Gets firewall address objects.

    """
    addr_name = addr.with_prefixlen
    address = []
    address += [f'{_SP} edit "{addr_name}"']
    if verbose:
      addr_comment = _DEFAULT_COMMENT
      if len(addr.text):
        addr_comment += " (" + addr.text + ")"
      address += [f'{_SP * 2} set comment "{self.fix_comment_length(addr_comment)}"']
    if not isinstance(addr, nacaddr.IPv6):
      address += [f'{_SP * 2} set subnet {addr_name}']
    if isinstance(addr, nacaddr.IPv6):
      address += [f'{_SP * 2} set ip6 {addr_name}']
    address += [_SP + 'next']

    return address

  def get_fw_addrgrps(self, ip_v=4):
    """Returns the collected address groups."""
    addrgrps = []
    for addrgrp_name, addrgrp_item in self._dict_addrgrps.items():
      if addrgrp_item[0] == ip_v:
        address = addrgrp_item[1]
        exclude_address = addrgrp_item[2]
        addrgrps += [f'{_SP} edit "{addrgrp_name}"']
        if self.verbose:
          addrgrps += [f'{_SP * 2} set comment "{_DEFAULT_COMMENT}"']
        if address:
          addrgrps += [f'{_SP * 2} set member {" ".join(f"\"{v}\"" for v in address)}']
        else:
          addrgrps += [_SP * 2 + 'set member "all"']
        if exclude_address:
          addrgrps += [_SP * 2 + 'set exclude enable']
          addrgrps += [f'{_SP * 2} set exclude-member {" ".join(f"\"{v}\"" for v in exclude_address)}']
        addrgrps += [_SP + 'next']

    return addrgrps

  def get_port_range(self, port):
    """
    Returns the port range as a string.

    If the input port is a single integer, returns that value.
    If the input port is a list of two integers, returns a range string (e.g. "1-10").

    :param port: The port number or list of port numbers
    :return: A string representing the port range
    """
    port_range = ''
    if len(port) == 1:
        port_range = str(port[0])
    elif len(port) > 1:
        port_range = str(port[0])
        if port[0] != port[1]:
            port_range = str(min(port[0], port[1])) + '-' + str(max(port[0], port[1]))

    return port_range

  def get_fw_services(self):
    """Returns the collected services."""
    fw_services = []
    for service_name in sorted(self._dict_services.keys()):
      fw_services += [_SP + 'edit ' + service_name]
      if self.verbose:
        fw_services += [f'{_SP * 2} set comment {_DEFAULT_COMMENT}']
      for service_item in self._dict_services[service_name]:
        fw_services += [_SP * 2 + service_item]
      fw_services += [_SP + 'next']

    return fw_services

  def get_fw_svcgrps(self):
    """Returns the collected service groups."""
    svcgrps = []
    for svcgrp, value in self._dict_svcgrps.items():
      svcgrps += [f'{_SP} edit {svcgrp}']
      if self.verbose:
        svcgrps += [f'{_SP * 2} set comment {_DEFAULT_COMMENT}']
      svcgrps += [_SP * 2 + value]
      svcgrps += [_SP + 'next']

    return svcgrps

  def get_fw_schedules(self):
    """Returns the collected schedules."""
    schedules = []
    for schedule_name, schedule_date in self._dict_schedules.items():
      schedules.extend([f'{_SP} edit {schedule_name}',
                        f'{_SP * 2} set end {schedule_date}',
                        'next'])
    return schedules

  def process_action_setting(self, action):
    """Process reject action."""
    found_action = _ACTION_TABLE.get(action)
    if found_action == 'reject':
      self._sys_settings.add('set deny-tcp-with-icmp enable')

    return action

  def add_address_to_fw_addrgrps(
      self,
      addrgrp_name,
      address,
      address_exclude):
    """Add address and exclude to address group store."""
    address_v4 = [x.with_prefixlen for x in address if
                  not isinstance(x, nacaddr.IPv6)]
    address_v6 = [x.with_prefixlen for x in address if
                  isinstance(x, nacaddr.IPv6)]
    address_exclude_v4 = [x.with_prefixlen for x in address_exclude if
                          not isinstance(x, nacaddr.IPv6)]
    address_exclude_v6 = [x.with_prefixlen for x in address_exclude if
                          isinstance(x, nacaddr.IPv6)]

    if address_exclude_v6:
      raise FortiGateValueError(
          'Exclude IPv6 address is unsupported: {}'.join([f'{x.with_prefix_len}' for x in address_exclude_v6]))

    addr_names = []
    if address_v4 or address_exclude_v4:
      addr_name = self.generate_address_or_addrgrp(
          addrgrp_name, address_v4, address_exclude_v4, 4)
      addr_names += [(4, addr_name)]

    if address_v6:
      addr_name6 = self.generate_address_or_addrgrp(
          addrgrp_name + '6', address_v6, None, 6)
      addr_names += [(6, addr_name6)]

    return addr_names or 'all'

  def generate_address_or_addrgrp(
      self,
      addrgrp_name,
      address,
      address_exclude,
      ip_v):
    """
    Generates an address or address group.

    Args:
        addrgrp_name: a string. name of address group
        address: a string. ipv4 or ipv6 address
        address_exclude: a string. ipv4 or ipv6 address
        ip_v: an integer. 4 or 6 for ipVersion

    Returns: string

    """
    if not address and not address_exclude:
      return 'all'

    if not address_exclude:
      if len(address) == 1:
        return address[0]

    if addrgrp_name not in self._dict_addrgrps:
      self._dict_addrgrps[addrgrp_name] = [
          ip_v, address, address_exclude]

    return addrgrp_name

  def get_defined_service(self, protocol, port):
    """return service if find service in defined map."""
    try:
      service = FortigatePortMap.get_protocol(protocol, port)
      return service
    except FortiGatePortDoesNotExistError:
      pass

    return None

  def add_service_to_fw_services(self, term_name, protocol_ports):
    """Add service to services store."""
    protocols = set()
    portranges = set()
    for protocol, portrange in protocol_ports.items():
      protocols.add(protocol)
      for range1 in portrange:
        portranges.add(str(range1))

    service_name = term_name + "-svc"
    if service_name not in self._dict_services:
      protocol_set = set()
      for protocol, port_ranges in protocol_ports.items():
        portrange_str = ' '.join(str(v) for v in sorted(port_ranges))
        protocol_set.add(
            f'set {protocol.lower()}-portrange {portrange_str}')

      self._dict_services[service_name] = sorted(protocol_set)

    return service_name

  def add_icmp_to_fw_services(
      self,
      protocol,
      icmp_type,
      normalized_icmptype,
      icmp_code):
    """
    Processes ICMP Additions to Firewall Services.

    """
    # icmp-types
    if not normalized_icmptype and not icmp_code:
      return 'ALL_ICMP6' if protocol == 'icmpv6' else 'ALL_ICMP'

    icmp_service_name = protocol + '-type-' + icmp_type + \
              (('-' + str(icmp_code)) if icmp_code else '')
    if icmp_service_name not in self._dict_services:
      protocol_set = []
      protocol_set += [f'set protocol {"ICMP6" if protocol == "icmpv6" else "ICMP"}']
      if normalized_icmptype:
        protocol_set += [f'set icmptype {normalized_icmptype}']
      if icmp_code:
        protocol_set += [f'set icmpcode {str(icmp_code)}']

      self._dict_services[icmp_service_name] = protocol_set

    return icmp_service_name

  def add_icmp_service_grp(self, term_name, icmp_service_grp):
    """
    Add an ICMP service group to the FortiGate configuration.

    Args:
        term_name (str): The name of the term.
        icmp_service_grp (list): A list of members to include in the service group.

    Returns:
        str: The name of the new service group, or the name of an existing one if it already exists.
    """
    icmp_service_grp_name = term_name + "-svcgrp"
    if icmp_service_grp_name not in self._dict_svcgrps:
      icmp_members = 'set member ' + (' ').join(sorted(icmp_service_grp))
      for key, value in self._dict_svcgrps.items():
        if icmp_members == value:
          return key
      self._dict_svcgrps[icmp_service_grp_name] = icmp_members

    return icmp_service_grp_name

  def add_expiration_to_fw_schedules(self, expiration):
    """Add expiry date to schedule store."""
    schedule_name = expiration[-10:] + '_' + expiration[:5]
    if schedule_name not in self._dict_schedules:
      self._dict_schedules[schedule_name] = expiration
    return schedule_name

  def fix_comment_length(self, comment):
    """Return a comment which is equal or shorter than _COMMENT_MAX_LENGTH.
       _COMMENT_MAX_LENGTH truncated as necessary.
    """
    return comment[:_COMMENT_MAX_LENGTH]


class Term(aclgenerator.Term):
  """Single Firewall Policy."""

  _PLATFORM = 'fortigate'
  _NGFW_MODE = 'profile-based'
  CURRENT_ID = 0

  def __init__(self, term, object_container, verbose=True):
    super().__init__(term)
    self._term = term
    self._obj_container = object_container
    self._term.verbose = verbose

    self.id_ = type(self).CURRENT_ID
    if type(self).CURRENT_ID > 0:
      type(self).CURRENT_ID += 1

  def _get_services_name(self, protocols, destination_ports, source_ports):
    """Get the service name, if not exist create it.

  Args:
    protocols: list of protocols
    destination_ports: list of destination ports
    source_ports: list of source ports

  Returns:
    string (all services separated by spaces).
  """

    ports = set()
    # fortigate does not allow empty destination_ports
    if not destination_ports and source_ports:
      # source ports only, to set destination ports = 1-65535
      destination_ports.append((1, 65535))

    if len(destination_ports):
      for destination_port in destination_ports:
        dest_port_range = self._obj_container.get_port_range(destination_port)
        if source_ports:
          for source_port in source_ports:
            src_port_range = self._obj_container.get_port_range(source_port)
            ports.add(dest_port_range + ':' + src_port_range)
        else:
          ports.add(dest_port_range)

    if not ports:
      ports.add('all')

    ports = sorted(ports)

    services = set()
    portranges = {}
    for protocol in protocols:
      if protocol in {'icmp', 'icmpv6'}:
        ip_v = 4 if protocol == 'icmp' else 6
        icmp_type_dict = {}
        for icmp_type in self._term.icmp_type:
          normalized_icmptype = self.NormalizeIcmpTypes(
              [icmp_type], protocols, ip_v)
          if normalized_icmptype:
            icmp_type_dict[icmp_type] = normalized_icmptype[0]

        icmp_service_grp = set()
        icmp_service_name = ''
        for icmp_type in sorted(
            icmp_type_dict, key=icmp_type_dict.get):
          if self._term.icmp_code:
            for each_code in sorted(self._term.icmp_code):
              icmp_service_name = self._obj_container.add_icmp_to_fw_services(
                  protocol, icmp_type, icmp_type_dict[icmp_type], each_code)
              icmp_service_grp.add(icmp_service_name)
          else:
            icmp_service_name = self._obj_container.add_icmp_to_fw_services(
                protocol,
                icmp_type,
                icmp_type_dict[icmp_type],
                self._term.icmp_code)
            icmp_service_grp.add(icmp_service_name)

        if len(icmp_service_grp) > 1:
          service = self._obj_container.add_icmp_service_grp(
              self._term.name, icmp_service_grp)
        else:
          service = icmp_service_name
        services.add(service)
      else:
        for port in ports:
          service = self._obj_container.get_defined_service(protocol, port)
          if service:
            if service == 'ALL_SCTP':
              if protocol not in portranges:
                portranges[protocol] = set()
              portranges[protocol].add('1-65535')
            else:
              services.add(service)
          else:
            if protocol not in portranges:
              portranges[protocol] = set()
            portranges[protocol].add(port)

    if portranges:
      service = self._obj_container.add_service_to_fw_services(
          self._term.name, portranges)
      services.add(service)

    return ' '.join(sorted(services)) or 'ALL'

  def _generate_address_names(self, *addresses):
    """Generate the addresses names (object-network names)."""
    for group in addresses:
      for addr in group:
        if addr:
          self._obj_container._dict_addresses.add(addr)

  def _process_verbatim_term(self):
    """Process verbatim term output"""
    # If Term includes verbatim token only
    # Warning and skip this term
    if not _SUPPORT_VERBATIM_TERM:
      logging.warning(
          'WARNING: Term %s is a verbatim term. '
          'term will not be rendered.',
          self.term.name)
      return ''
    # output verbatim term and warning
    output = []
    for verbatim_line in self.term.verbatim:
      platform, contents = verbatim_line
      if platform == self._PLATFORM:
        output += [str(contents)]
    logging.warning(
        'WARNING: Term %s is a verbatim term. '
        'to ensure the term output is'
        'valid FortiGate items.', self.term.name)
    return (_SP * 2 + ('\n' + _SP * 2).join(output)) if output else ''

  def _process_verbatim_item(self):
    """Process verbatim output"""
    # Term verbatim output
    output = []
    if self.term.verbatim:
      for verbatim_line in self.term.verbatim:
        platform, contents = verbatim_line
        if platform == self._PLATFORM:
          output += [_SP * 2 + str(contents)]

    return output

  def _convert_date(self, expiration):
    """Covert date format yyyy-mm-dd hh:mi to hh:mi yyyy/mm/dd."""
    try:
      schedule_date = expiration.strftime('%H:%M %Y/%m/%d')
      return schedule_date
    except ValueError as e:
      raise FortiGateScheduleDateError('Expiration is invalid datetime format.') from e

  def __str__(self):
    lines = []

    # process verbatim term
    if self.term.verbatim and (
        not self.term.protocol or not self.term.action):
      return self._process_verbatim_term()

    # Not support next action, skip this term
    action = self._obj_container.process_action_setting(
        self._term.action[0])
    if action == 'next':
      return ''

    self._generate_address_names(
        self._term.destination_address,
        self._term.source_address,
        self._term.destination_address_exclude,
        self._term.source_address_exclude)

    dest_addresses = self._obj_container.add_address_to_fw_addrgrps(
        self._term.name + '-dstgrp',
        self._term.destination_address,
        self._term.destination_address_exclude)
    src_addresses = self._obj_container.add_address_to_fw_addrgrps(
        self._term.name + '-srcgrp',
        self._term.source_address,
        self._term.source_address_exclude)

    services = self._get_services_name(
        sorted(
            self._term.protocol),
        self._term.destination_port,
        self._term.source_port)

    schedule_name = None
    if self._term.expiration:
      schedule_date = self._convert_date(self._term.expiration)
      schedule_name = self._obj_container.add_expiration_to_fw_schedules(
          schedule_date)

    lines += [f"{_SP * 2} set name {self._term.name}"]
    # Owner (implement as comment)
    if not self._term.comment:
      self._term.comment = [_DEFAULT_COMMENT]
    if self._term.owner:
      self._term.comment += [f"Owner: {self._term.owner}"]
    if self._term.comment and self._term.verbose:
       lines += [f'{_SP * 2} set comments "{self._obj_container.fix_comment_length((" ").join(self._term.comment))}"']
    # fortigate local-in policy exception
    if self._term.destination_interface and not self._term.source_interface:
      lines += [f"{_SP * 2} set intf {self._term.destination_interface or 'any'}"]
    else:
      lines += [f"{_SP * 2} set srcintf {self._term.source_interface or 'any'}"]
      lines += [f"{_SP * 2} set dstintf {self._term.destination_interface or 'any'}"]      
    exist_src6 = False
    exist_dst6 = False
    if isinstance(dest_addresses, list):
      for (ip_v, addr_name) in dest_addresses:
        lines += [f"{_SP * 2} set {('dstaddr' if ip_v == 4 else 'dstaddr6')} '{addr_name}'"]
        if ip_v == 6:
          exist_dst6 = True
    else:
      lines += [f"{_SP * 2} set dstaddr '{dest_addresses}'"]
    if isinstance(src_addresses, list):
      for (ip_v, addr_name) in src_addresses:
        lines += [f"{_SP * 2} set {('srcaddr' if ip_v == 4 else 'srcaddr6')} '{addr_name}'"]
        if ip_v == 6:
          exist_src6 = True
    else:
      lines += [f"{_SP * 2} set srcaddr '{src_addresses}'"]
    if exist_src6 and not exist_dst6:
      lines += [_SP * 2 + 'set dstaddr6 "all"']
    elif not exist_src6 and exist_dst6:
      lines += [_SP * 2 + 'set srcaddr6 "all"']

    lines += [f"{_SP * 2} set action {action if action == 'accept' else 'deny'}"]
    if action == 'reject':
      lines += [_SP * 2 + 'set send-deny-packet enable']

    if services:
      if self._NGFW_MODE == 'policy-based':
        lines += [_SP * 2 + 'set enforce-default-app-port disable']
      lines += [f"{_SP * 2} set service '{services}'"]
    else:
      if self._NGFW_MODE == 'policy-based':
        lines += [_SP * 2 + 'set enforce-default-app-port enable']
  
    if self._NGFW_MODE == 'policy-based' and self._term.fortigate_application_id:
      lines  += [f"{_SP * 2} set application {' '.join(str(v) for v in sorted(self._term.fortigate_application_id))}"]

    lines  += [f"{_SP * 2} set schedule {schedule_name if schedule_name else 'always'}"]

    if self._term.logging:
      if self._term.logging == 'log-both':
        lines += [_SP * 2 + 'set logtraffic all']
        lines += [_SP * 2 + 'set logtraffic-start enable']
      elif self._term.logging == 'disable':
        lines += [_SP * 2 + 'set logtraffic disable']
      else:
        lines += [_SP * 2 + 'set logtraffic all']

    return '\n'.join(lines)


class Fortigate(aclgenerator.ACLGenerator):
  """A Fortigate policy object."""

  _PLATFORM = 'fortigate'
  _NGFW_MODE = 'profile-based'
  _DEFAULT_PROTOCOL = 'ALL'
  SUFFIX = '.fcl'

  def __init__(self, *args, **kwargs):
    self._obj_container = ObjectsContainer()
    super().__init__(*args, **kwargs)

  def _BuildTokens(self):
    """Build supported tokens for platform.

  Returns:
    tuple containing both supported tokens and sub tokens.
  """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()
    supported_tokens |= {'interface',
                         'source_interface',
                         'destination_interface',
                         'source_address_exclude',
                         'destination_address_exclude',
                         'icmp_type',
                         'icmp_code',
                         'fortigate_application_id'}

    supported_sub_tokens.update({'option': {'tcp-established'},
                                 # Warning, some of these are mapped
                                 # differently. See _ACTION_TABLE
                                 'action': {'accept', 'deny',
                                            'next', 'reject',
                                            'reject-with-tcp-rst'}})

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Translate Capirca pol to fortigate pol."""
    self.fortigate_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    term_dup_check = set()

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      # fortigate option format:
      #   target:: fortigate from-id n
      # target:: fortigate from-id n ngfw-mode profile-based |
      # policy-based
      filter_options = header.FilterOptions(self._PLATFORM)

      verbose = True
      if 'noverbose' in filter_options:
        filter_options.remove('noverbose')
        verbose = False

      self._obj_container.verbose = verbose

      my_filter = {}
      if len(filter_options) == 1:
        my_filter[filter_options[0]] = ''
      if len(filter_options) > 1:
        my_filter[filter_options[0]] = filter_options[1]
      if len(filter_options) > 3:
        for key in filter_options:
          if key == my_filter[2]:
            raise FilterError('Fortigate filter arguments are duplicated: ' + key)
        my_filter[filter_options[2]] = filter_options[3]

      # default from-id is 0
      Term.CURRENT_ID = 0
      # default ngfw_mode = profile-based
      self.ngfw_mode = 'profile-based'
      for filter_key, filter_val in my_filter.items():
        if filter_key == 'from-id':
          from_id = int(filter_val)
          if from_id < 1:
            raise FilterError(
                'FortiGate from-id must be more than zero')
          Term.CURRENT_ID = int(from_id)
        elif filter_key == 'ngfw-mode':
          if filter_val not in ['profile-based', 'policy-based']:
            raise FilterError('FortiGate ngfw-mode only supports profile-based or policy-based')          
          self.ngfw_mode = filter_val
        else:
          raise FilterError(
              'FortiGate only support from-id and ngfw-mode filter')

      Term._NGFW_MODE = self.ngfw_mode

      for term in terms:
        term.name = self.FixTermLength(term.name)

        filter_name = header.FilterName(self._PLATFORM)
        if term.stateless_reply:
          logging.warning(
              'WARNING: Term %s in policy %s is a stateless reply '
              'term and will not be rendered. FortiGates are stateful',
              term.name,
              filter_name)
          continue
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info(
                'INFO: Term %s in policy %s expires '
                'in less than two weeks.',
                term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning(
                'WARNING: Term %s in policy %s is expired and '
                'will not be rendered.',
                term.name, filter_name)
            continue
        if term.name in term_dup_check:
          raise FortiGateDuplicateTermError(f"You have a duplicate term: {term.name}")
        term_dup_check.add(term.name)

        new_term = Term(term, self._obj_container, verbose)

        self.fortigate_policies += [(header, term.name, new_term)]

  def _get_fw_policies(self):
    target_policies = []
    policy_id = 0
    for (_, _, term) in self.fortigate_policies:
      term_str = str(term)
      if term_str != '':
        target_policies += [_SP + f'edit {policy_id}']
        target_policies += [term_str]
        target_policies += [_SP + 'next']
        policy_id += 1

    return target_policies

  def __str__(self):
    fw_policies = self._get_fw_policies()

    start_sys_settings = ['config sys setting']
    start_addresses_v4 = ['config firewall address']
    start_addresses_v6 = ['config firewall address6']
    start_addrgrps_v4 = ['config firewall addrgrp']
    start_addrgrps_v6 = ['config firewall addrgrp6']
    start_services = ['config firewall service custom']
    start_svcgrps = ['config firewall service group']
    start_schedules = ['config firewall schedule onetime']
    start_policies = []
    if self._NGFW_MODE == 'profile-based':
      start_policies = ['config firewall policy']
    else:
      start_policies = ['config firewall security-policy']
    end = ['end']

    sys_settings = []
    if self._obj_container.get_sys_settings():
      sys_settings = start_sys_settings + \
               self._obj_container.get_sys_settings() + \
               end + ['']

    fw_addresses = []
    if self._obj_container.get_fw_addresses(4):
      fw_addresses += start_addresses_v4 + \
              self._obj_container.get_fw_addresses(4) + \
              end + ['']
    if self._obj_container.get_fw_addresses(6):
      fw_addresses += start_addresses_v6 + \
              self._obj_container.get_fw_addresses(6) + \
              end + ['']

    fw_addr_grps = []
    if self._obj_container.get_fw_addrgrps(4):
      fw_addr_grps += start_addrgrps_v4 + \
              self._obj_container.get_fw_addrgrps(4) + \
              end + ['']
    if self._obj_container.get_fw_addrgrps(6):
      fw_addr_grps += start_addrgrps_v6 + \
              self._obj_container.get_fw_addrgrps(6) + \
              end + ['']

    fw_services = []
    if self._obj_container.get_fw_services():
      fw_services = start_services + \
              self._obj_container.get_fw_services() + \
              end + ['']

    fw_svc_grps = []
    if self._obj_container.get_fw_svcgrps():
      fw_svc_grps = start_svcgrps + \
              self._obj_container.get_fw_svcgrps() + \
              end + ['']

    fw_schedules = []
    if self._obj_container.get_fw_schedules():
      fw_schedules = start_schedules + \
               self._obj_container.get_fw_schedules() + \
               end + ['']

    fw_policies = start_policies + fw_policies + end

    target = sys_settings + fw_addresses + fw_addr_grps + \
         fw_services + fw_svc_grps + fw_schedules + fw_policies

    return '\n'.join(target)
