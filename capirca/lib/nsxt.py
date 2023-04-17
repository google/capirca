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

import json

from absl import logging
from capirca.lib import aclgenerator

_ACTION_TABLE = {
    'accept': 'ALLOW',
    'deny': 'DROP',
    'reject': 'REJECT',
    'reject-with-tcp-rst': 'REJECT',  # tcp rst not supported
}

_NSXT_SUPPORTED_KEYWORDS = [
    'name',
    'action',
    'resource_type',
    'display_name',
    'marked_for_delete',
    'overridden',
    'rule_id',
    'sequence_number',
    'sources_excluded',
    'destinations_excluded',
    'source_groups',
    'destination_groups',
    'services',
    'profiles',
    'logged',
    'scope',
    'disabled',
    'notes',
    'direction',
    'tag',
    'ip_protocol',
    'is_default',
    'protocol',
    'destination_port',
    'source_address',
    'destination_address',
    'source_port'
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

  def __init__(self, protocol, source_ports, destination_ports, icmp_types):
    """Setting things up.

    Args:
      protocol: str, protocol.
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

  def __init__(self, term, filter_type, applied_to=None, af=4):
    self.term = term
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    self.filter_type = filter_type
    self.applied_to = applied_to

  def __str__(self):
    """Convert term to a rule string.

    Returns:
      A rule as a string.

    """
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'nsxt' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'nsxt' in self.term.platform_exclude:
        return ''

    term_keywords = self.term.__dict__
    unsupported_keywords = []
    for key in term_keywords:
      if term_keywords[key]:
        if ('translated' not in key) and (key not in _NSXT_SUPPORTED_KEYWORDS):
          unsupported_keywords.append(key)
    if unsupported_keywords:
      logging.warning('WARNING: The keywords %s in Term %s are not supported '
                      'in Nsxt ', unsupported_keywords, self.term.name)

    name = self.term.name

    notes = ''
    if self.term.comment:
      notes = '\n'.join(self.term.comment)

    action = 'ALLOW'
    if self.term.action:
      action = _ACTION_TABLE.get(self.term.action[0])

    source_address = ['ANY']
    if self.term.source_address:
      source_address = []
      for i in self.term.source_address:
        source_address.append(str(i))

    destination_address = ['ANY']
    if self.term.destination_address:
      destination_address = []
      for i in self.term.destination_address:
        destination_address.append(str(i))

    rule = {
        'action': action,
        'resource_type': 'Rule',
        'display_name': name,
        'source_groups': source_address,
        'destination_groups': destination_address,
        # Set mandatory services to ANY, as service_entries will be used
        'services': ['ANY'],
        'profiles': ['ANY'],
        'scope': ['ANY'],
        'logged': bool(self.term.logging),
        'notes': notes,
        'direction': 'IN_OUT',
        'ip_protocol': 'IPV4_IPV6'
    }

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


class Nsxt(aclgenerator.ACLGenerator):
  """nsxt rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by nsxt policy.

  Attributes:
    pol: policy.Policy object

  Raises:
  UnsupportednsxtAccessListError: Raised when we're give a non named access
  list.

  """

  _PLATFORM = 'nsxt'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.nsxt'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration', 'logging'])
  _FILTER_OPTIONS_DICT = {}

  def _TranslatePolicy(self, pol, exp_info):
    self.nsxt_policies = []

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      if len(filter_options) >= 2:
        filter_name = filter_options[1]

      self._ParseFilterOptions(filter_options)

      filter_type = ''
      applied_to = ''

      term_names = set()
      new_terms = []
      for term in terms:
        # Check for duplicate terms
        if term.name in term_names:
          raise NsxtDuplicateTermError('There are multiple terms named: %s' %
                                       term.name)
        term_names.add(term.name)

        term.name = self.FixTermLength(term.name)

        new_terms.append(Term(term, filter_type, applied_to, 4))

      self.nsxt_policies.append((header, filter_name, [filter_type],
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
    for (_, _, _, terms) in self.nsxt_policies:
      rules = [json.loads(str(term)) for term in terms]

    section_name = self._FILTER_OPTIONS_DICT['section_name']
    section_id = self._FILTER_OPTIONS_DICT['section_id']
    applied_to = self._FILTER_OPTIONS_DICT['applied_to']

    policy = {
        'rules': rules,
        'resource_type': 'SecurityPolicy',
        'display_name': section_name,
        'id': section_id if section_id is not None else section_name,
        'category': 'Application',
        'is_default': 'false',
        'scope': [applied_to]
    }

    return json.dumps(policy, indent=2)
