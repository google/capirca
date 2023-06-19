# Copyright 2023 The Capirca Project Authors All Rights Reserved.
# Copyright 2023 VMware, Inc. SPDX-License-Identifier: Apache-2.0
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

"""nsxt generator."""

import datetime
import json
from typing import Literal, TypedDict, Optional, Union, Tuple

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import policy  # for typing information

_ACTION_TABLE = {
    'accept': 'ALLOW',
    'deny': 'DROP',
    'reject': 'REJECT',
    'reject-with-tcp-rst': 'REJECT',  # tcp rst not supported
}

_NSXT_SUPPORTED_KEYWORDS = [
    'name',
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'logging',
]

_PROTOCOLS = {
    1: 'ICMPv4',
    6: 'TCP',
    17: 'UDP',
    58: 'ICMPv6'
}


# generic error class
class Error(Exception):
  """Generic error class."""
  pass


class UnsupportedNsxtAccessListError(Error):
  """Raised when we're give a non named access list."""
  pass


class NsxtAclTermError(Error):
  """Raised when there is a problem in a nsxt access list."""
  pass


class NsxtDuplicateTermError(Error):
  """Raised when there is a duplicate."""
  pass


class NsxtUnsupportedCriteriaOperatorError(Error):
  """Raised when an unsupported criteria comparison operator is encountered."""
  pass


class NsxtUnsupportedManyPoliciesError(Error):
  """Raised when there are many policies/headers specified."""
  pass


class ServiceEntries:
  """Represents service entries for a rule."""

  def __init__(self, protocol: int, source_ports: list[Tuple[str, str]],
               destination_ports: list[Tuple[str, str]],
               icmp_types: list[int]):
    """Setting things up.

    Args:
      protocol: int, protocol.
      source_ports: str list or none, the source port.
      destination_ports: str list or none, the destination port.
      icmp_types: icmp-type numeric specification (if any).
    """
    self.protocol = protocol
    self.source_ports = source_ports
    self.destination_ports = destination_ports
    self.icmp_types = icmp_types

  def get(self):
    """Returns list of services."""
    # Handle ICMP and ICMPv6
    if self.protocol == 1 or self.protocol == 58:
      service = {
          'protocol': _PROTOCOLS[self.protocol],
          'resource_type': 'ICMPTypeServiceEntry',
      }
      if not self.icmp_types:
        return [service]

      # Handle ICMP types
      services = []
      for icmp_type in self.icmp_types:
        new_service = service.copy()
        new_service['icmp_type'] = icmp_type
        services.append(new_service)
      return services

    # Handle TCP and UDP
    elif self.protocol == 6 or self.protocol == 17:
      service = {
          'l4_protocol': _PROTOCOLS[self.protocol],
          'resource_type': 'L4PortSetServiceEntry',
      }

      # Handle Layer 4 Ports
      if self.source_ports:
        source_ports = [f'{p[0]}-{p[1]}' for p in self.source_ports]
        service['source_ports'] = source_ports

      if self.destination_ports:
        destination_ports = [f'{p[0]}-{p[1]}' for p in self.destination_ports]
        service['destination_ports'] = destination_ports
      return [service]
    else:
      return []


class Term(aclgenerator.Term):
  """Creates a single ACL Term for NSX-T."""

  def __init__(self, term: policy.Term,
               filter_type: Literal['inet', 'inet6', 'mixed'],
               af: Literal[4, 6] = 4):
    self.term = term
    # Our caller should have already verified the filter type.
    assert filter_type in ['inet', 'inet6', 'mixed']
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    self.filter_type = filter_type

  def __str__(self):
    """Convert term to a rule string.

    Returns:
      A rule as a string. Either valid JSON or an empty string.

    Raises:
      NsxtAclTermError: When unknown icmp-types, options or other unsupported
          features are specified

    """
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'nsxt' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'nsxt' in self.term.platform_exclude:
        return ''

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(term=self.term.name,
                                                    proto=self.term.protocol,
                                                    af=self.filter_type))
      return ''

    # Term verbatim is not supported
    if self.term.verbatim:
      raise NsxtAclTermError(
          'Verbatim are not implemented in standard ACLs')

    # Term option is not supported
    if self.term.option:
      for opt in [str(single_option) for single_option in self.term.option]:
        if((opt.find('tcp-established') == 0)
           or (opt.find('established') == 0)):
          return ''
        else:
          raise NsxtAclTermError(
              'Option are not implemented in standard ACLs')

    # check for keywords Nsxt does not support
    term_keywords = self.term.__dict__
    unsupported_keywords = []
    for key in term_keywords:
      if term_keywords[key]:
        # translated is obj attribute not keyword
        if ('translated' not in key) and (key not in _NSXT_SUPPORTED_KEYWORDS):
          unsupported_keywords.append(key)
    if unsupported_keywords:
      logging.warning('WARNING: The keywords %s in Term %s are not supported '
                      'in Nsxt ', unsupported_keywords, self.term.name)

    name = self.term.name

    notes = ''
    if self.term.comment:
      notes += '\n'.join(self.term.comment)

    action = 'ALLOW'
    if self.term.action:
      action = _ACTION_TABLE.get(self.term.action[0])

    # for mixed filter type get both IPV4address and IPv6Address
    if self.filter_type == 'mixed':
      af_list = [4, 6]
    else:
      af_list = [self.af]

    # There can be many source and destination addresses.
    source_address: list[nacaddr.IPType] = []
    destination_address: list[nacaddr.IPType] = []
    source_addr = []
    destination_addr = []

    source_v4_addr = []
    source_v6_addr = []
    dest_v4_addr = []
    dest_v6_addr = []

    # Fix addresses for each of the IP protocol versions we support.
    # This includes fixing up exclusion addresses as needed.
    for af in af_list:
      # source address
      if self.term.source_address:
        source_address: list[nacaddr.IPType] = self.term.GetAddressOfVersion(
            'source_address', af)
        source_address_exclude: list[nacaddr.IPType] = (
            self.term.GetAddressOfVersion('source_address_exclude', af))
        if source_address_exclude:
          source_address: list[nacaddr.IPType] = nacaddr.ExcludeAddrs(
              source_address, source_address_exclude)

        if source_address:
          if af == 4:
            source_address: list[nacaddr.IPv4]
            source_v4_addr: list[nacaddr.IPv4] = source_address
          else:
            source_address: list[nacaddr.IPv6]
            source_v6_addr: list[nacaddr.IPv6] = source_address
        source_addr = source_v4_addr + source_v6_addr

      # destination address
      if self.term.destination_address:
        destination_address: list[
            nacaddr.IPType] = self.term.GetAddressOfVersion(
                'destination_address', af)
        destination_address_exclude: list[nacaddr.IPType] = (
            self.term.GetAddressOfVersion('destination_address_exclude', af))
        if destination_address_exclude:
          destination_address: list[nacaddr.IPType] = nacaddr.ExcludeAddrs(
              destination_address,
              destination_address_exclude)

        if destination_address:
          if af == 4:
            destination_address: list[nacaddr.IPv4]
            dest_v4_addr: list[nacaddr.IPv4] = destination_address
          else:
            destination_address: list[nacaddr.IPv6]
            dest_v6_addr: list[nacaddr.IPv6] = destination_address
        destination_addr = dest_v4_addr + dest_v6_addr

    # Check for mismatch IP for source and destination address for mixed filter
    if self.filter_type == 'mixed':
      if source_addr and destination_addr:
        if source_v4_addr and not dest_v4_addr:
          source_addr = source_v6_addr
        elif source_v6_addr and not dest_v6_addr:
          source_addr = source_v4_addr
        elif dest_v4_addr and not source_v4_addr:
          destination_addr = dest_v6_addr
        elif dest_v6_addr and not source_v6_addr:
          destination_addr = dest_v4_addr

        if not source_addr or not destination_addr:
          logging.warning('Term %s will not be rendered as it has IPv4/IPv6 '
                          'mismatch for source/destination for mixed address '
                          'family.', self.term.name)
          return ''

    rule = {
        'action': action,
        'resource_type': 'Rule',
        'display_name': name,
        'source_groups': [str(i) for i in source_addr] or ['ANY'],
        'destination_groups': [str(i) for i in destination_addr] or ['ANY'],
        # Set mandatory services to ANY, as service_entries will be used
        'services': ['ANY'],
        'profiles': ['ANY'],
        'scope': ['ANY'],
        'logged': bool(self.term.logging),
        'notes': notes,
        'direction': 'IN_OUT',
        'ip_protocol': '_'.join(['IPV%d' % af for af in af_list]),
    }

    # Compute protocols used in this term. Normalize the ICMP types.
    # Populate service entries (which is not done unless protocol is specified).
    if self.term.protocol:
      icmp_types = []
      services = []
      if self.term.icmp_type:
        icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                             self.term.protocol,
                                             self.af)

      protocol = [self.PROTO_MAP.get(p) for p in self.term.protocol]
      for proto in protocol:
        if proto != 'any':
          service = ServiceEntries(proto, self.term.source_port,
                                   self.term.destination_port, icmp_types)
          services.extend(service.get())
      rule['service_entries'] = services

    return json.dumps(rule)


class FilterOptions(TypedDict):
  section_name: str  # Display name of the SecurityPolicy.
  filter_type: Literal['inet', 'inet6', 'mixed']  # IP version to apply to.
  section_id: Optional[str]  # Numeric ID of the rule.
  applied_to: Union[str, Literal['ANY']]  # Security group to apply to.


class Nsxt(aclgenerator.ACLGenerator):
  """NSX-T rendering class.

  This class takes a policy object and renders the output into a syntax
  which is understood by nsxt policy.

  Attributes:
    pol: policy.Policy object

  Raises:
    UnsupportedNsxtAccessListError: Raised when we're give a non named access
  list.
  """

  _PLATFORM = 'nsxt'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nsxt'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration', 'logging', 'comment'])
  _FILTER_OPTIONS_DICT = {}

  def _TranslatePolicy(self, pol: policy.Policy, exp_info: int):
    self.nsxt_policies: list[Tuple[policy.Header, str, list[Term]]] = []
    current_date = datetime.datetime.utcnow().date()

    # Warn about policies that will expire in less than exp_info weeks.
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    filters: list[Tuple[policy.Header, list[policy.Term]]] = pol.filters
    for header, terms in filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = f'<{str(header)}>'  # Default name.
      if filter_options:
        # filter_options[0]: policy name
        # filter_options[1]: type (inet, inet6, mixed)
        # Used in some of the warnings below.
        filter_name = filter_options[0]

      # extract filter type, section id and applied-to, and store them
      self._ParseFilterOptions(filter_options)

      # One of 'inet', 'inet6' or 'mixed'.
      filter_type: Literal['inet', 'inet6', 'mixed'] = (
          self._FILTER_OPTIONS_DICT['filter_type'])

      term_names = set()
      new_terms = []
      for term in terms:
        # Check for duplicate terms
        if term.name in term_names:
          raise NsxtDuplicateTermError('There are multiple terms named: %s' %
                                       term.name)
        term_names.add(term.name)

        # Warn about terms about to expire. Do not render expired terms.
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue

        # Get the mapped action value
        # If there is no mapped action value term is not rendered
        mapped_action = _ACTION_TABLE.get(str(term.action[0]))
        if not mapped_action:
          logging.warning('WARNING: Action %s in Term %s is not valid and '
                          'will not be rendered.', term.action, term.name)
          continue

        term.name = self.FixTermLength(term.name)

        # Generate terms depending on whether the filter_type is one of 'inet',
        # 'inet6' or 'mixed' (for both v4 and v6).

        if filter_type == 'inet':
          af = 'inet'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue
          new_terms.append(Term(term, filter_type, 4))

        elif filter_type == 'inet6':
          af = 'inet6'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue
          new_terms.append(Term(term, filter_type, 6))

        elif filter_type == 'mixed':
          if 'icmpv6' not in term.protocol:
            inet_term = self.FixHighPorts(term, 'inet')
            if not inet_term:
              continue
            new_terms.append(Term(inet_term, filter_type, 4))
          else:
            inet6_term = self.FixHighPorts(term, 'inet6')
            if not inet6_term:
              continue
            new_terms.append(Term(inet6_term, filter_type, 6))

        else:
          # This should have already been checked in _ParseFilterOptions.
          raise UnsupportedNsxtAccessListError(
              'Access list type %s not supported by %s' % (
                  filter_type, self._PLATFORM))

      self.nsxt_policies.append((header, filter_name,
                                 new_terms))

  def _ParseFilterOptions(self, filter_options):
    """Parses the target in header for filter type, section_id and applied_to.

    Args:
      filter_options: list of remaining target options

    Returns:
      A dictionary that contains fields necessary to create the firewall
      rule.

    Raises:
      UnsupportedNsxtAccessListError: Raised when we're give a non named access
      list.
    """
    # check for filter type
    if not 2 <= len(filter_options) <= 5:
      raise UnsupportedNsxtAccessListError(
          'Invalid Number of options specified: %d. Required options '
          'are: filter type and section name. Platform: %s' % (
              len(filter_options), self._PLATFORM))
    # mandatory section_name
    section_name = filter_options[0]
    # mandatory
    filter_type = filter_options[1]

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['inet', 'inet6', 'mixed']

    # check if filter type is renderable
    if filter_type not in good_filters:
      raise UnsupportedNsxtAccessListError(
          'Access list type %s not supported by %s (good types: %s)' % (
              filter_type, self._PLATFORM, str(good_filters)))

    section_id = None
    applied_to = 'ANY'
    filter_opt_len = len(filter_options)

    if filter_opt_len > 2:
      for index in range(2, filter_opt_len):
        if index == 2 and filter_options[2] != 'securitygroup':
          section_id = filter_options[2]
          continue
        if filter_options[index] == 'securitygroup':
          if index + 1 <= filter_opt_len - 1:
            securitygroup = filter_options[index + 1]
            if securitygroup[0] != '/':
              securitygroup = f'/infra/domains/default/groups/{securitygroup}'
            applied_to = securitygroup
            break
          else:
            raise UnsupportedNsxtAccessListError(
                'Security Group Id is not provided for %s' % (self._PLATFORM))

    self._FILTER_OPTIONS_DICT['section_name'] = section_name
    self._FILTER_OPTIONS_DICT['filter_type'] = filter_type
    self._FILTER_OPTIONS_DICT['section_id'] = section_id
    self._FILTER_OPTIONS_DICT['applied_to'] = applied_to

  def __str__(self):
    """Render the output of the nsxt policy."""
    if (len(self.nsxt_policies) > 1):
      raise NsxtUnsupportedManyPoliciesError('Only one policy can be rendered')

    # To support multiple policies, we would have to detect a change in the
    # section ID / section name specified in a header, and then output a list of
    # dicts. A pusher used to communicate with the NSX-T API would then have to
    # support seeing a list instead of a dict, and apply multiple policies.

    header, _, terms = self.nsxt_policies[0]
    # A term may be rendered as an empty string if it must not be rendered
    # under the current conditions (e.g. ICMPv6 term while rendering an IPv4
    # policy).
    rules = [json.loads(str(term)) for term in terms if str(term)]

    section_name = self._FILTER_OPTIONS_DICT['section_name']
    section_id = self._FILTER_OPTIONS_DICT['section_id']
    applied_to = self._FILTER_OPTIONS_DICT['applied_to']

    # compute the p4 tags
    description = ' '.join(aclgenerator.AddRepositoryTags(''))

    # add the header comment as well
    if header.comment:
      description += ' :: ' + ' :: '.join(header.comment)

    policy_json = {
        'rules': rules,
        'resource_type': 'SecurityPolicy',
        'display_name': section_name,
        'id': section_id if section_id is not None else section_name,
        'category': 'Application',
        'is_default': 'false',
        'scope': [applied_to],
        'description': description,
    }

    return json.dumps(policy_json, indent=2)
