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
#
# VERSION 1.01
# Fix the wrong use of notes instead of description, notes are supposed to be used for rule lock/unlock
# Add comment keyword instead of notes (comments are translated now to description in NSX-T API)
# Check description length against its maximum
# Add check for maximum number of rules
# Add support for term expiration
# Add a more granular management of ip_protocol and not blindly set it to IPV4_IPV6
# Fix bug convert 0.0.0.0/0 to ANY
# Add support for source_excluded
# Add support for verbose keyword
# Add check for mixed rule (v4 and v6) with v4 only source and no non-ANY v4 destination and v6 only source and no non-ANY v6 destination
# Add check for maximum number of source and destination IPs
# Fix issue when str of Term return nothing
# Add support for numerical protocol
# Fix bug when there's a single port, don't convert it into a range

"""nsxt generator."""

import json
import datetime

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr

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
  'comment',
  'direction',
  'tag',
  'ip_protocol',
  'is_default',
  'protocol',
  'icmp_type',
  'destination_port',
  'source_address',
  'destination_address',
  'source_port',
  'platform'
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
  """Raised when we're given a non named access list."""
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


class ExceededMaxTermsError(Error):
  """Raised when number of terms in a policy exceed _MAX_RULES_PER_POLICY."""
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
        #Is the return supposed to be in the for loop? Potential bug to be tested with multiple ICMP types
        return services

    # Handle TCP and UDP
    elif self.protocol == 6 or self.protocol == 17:
      service = {
        'l4_protocol': _PROTOCOLS[self.protocol],
        'resource_type': 'L4PortSetServiceEntry',
      }

      # Handle Layer 4 Ports
      if self.source_ports:
        source_port = []
        for p in self.source_ports:  
          # handle port range
          if p[0] != p[1]:
            source_ports += [f'{p[0]}-{p[1]}']
          # handle single port
          else:
            source_ports += [f'{p[0]}']
        service['source_ports'] = source_ports

      if self.destination_ports:
        destination_ports = []
        for p in self.destination_ports:
          # handle port range
          if p[0] != p[1]:
            destination_ports += [f'{p[0]}-{p[1]}']
          else:
            destination_ports += [f'{p[0]}']
        service['destination_ports'] = destination_ports
      return [service]

    # Handle other numerical protocols
    elif isinstance(self.protocol, int):
      service['protocol_number'] = f'{self.protocol}'
      service['resource_type'] = 'IPProtocolServiceEntry'
      return [service]

    else:
      return []

class Term(aclgenerator.Term):
  """Creates a single ACL Term for NSX-T."""

  _MAX_TERM_NAME_LENGTH = 255
  _MAX_TERM_COMMENT_LENGTH = 1024

  #Max numbers of addresses and service_entries per rule
  _MAX_TERM_ITEMS = 128

  def __init__(self, term, filter_type, applied_to=None, verbose=True):
    self.term = term
    # Our caller should have already verified the address family.
    self.filter_type = filter_type
    self.applied_to = applied_to
    self.verbose = verbose
    self.sources_excluded = False
    self.destinations_excluded = False


  def __str__(self):
    """Convert term to a rule string.

    Returns:
      A rule as a string.

    """
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'nsxt' not in self.term.platform:
        logging.warning('WARNING: nsxt not in platform statement of Term %s.',
                      self.term.name)
        return None
    if self.term.platform_exclude:
      if 'nsxt' in self.term.platform_exclude:
        logging.warning('WARNING: The platform nsxt excluded in Term %s.',
                self.term.name)
        return None

    # Verify if the term does not use an unsupported keyword
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

    description = ''
    # Set Rule description
    if self.term.comment and self.verbose:
      raw_comment = " ".join(self.term.comment)
      if len(raw_comment) > self._MAX_TERM_COMMENT_LENGTH:
        description = raw_comment[: self._MAX_TERM_COMMENT_LENGTH]
        logging.warning(
          "Term comment exceeds maximum length = %d; Truncating comment.",
          self._MAX_TERM_COMMENT_LENGTH,
        )
      else:
        description = raw_comment

    action = 'ALLOW'
    if self.term.action:
      action = _ACTION_TABLE.get(self.term.action[0])

    saddrs = None
    daddrs = None
    source_address = []
    destination_address = []
    src_type = None


    sources_excluded = False
    #Set sources_excluded if set to True
    if self.sources_excluded:
      sources_excluded = True

    destinations_excluded = False
    #Set destinations_excluded if set to True
    if self.destinations_excluded:
      destinations_excluded = True


    ip_protocol = "IPV4_IPV6"
    # Set Rule ip_protocol, source_groups and destination_groups
    # Handle IPv4 address-family
    if self.filter_type == '4':
      ip_protocol = "IPV4"
      # Handle source IPv4 addresses
      if self.term.GetAddressOfVersion("source_address", 4):
        saddrs = self.term.GetAddressOfVersion("source_address", 4)
        # Handle ANY source address
        if saddrs[0].with_prefixlen == "0.0.0.0/0":
          saddrs = "ANY"

      # Handle destination IPv4 addresses
      if self.term.GetAddressOfVersion("destination_address", 4):
        daddrs = self.term.GetAddressOfVersion("destination_address", 4)
        if daddrs[0].with_prefixlen == "0.0.0.0/0":
          daddrs = "ANY"

    # Handle IPv6 address-family
    elif self.filter_type == "6":
      ip_protocol = "IPV6"

      # Handle IPv6 source addresses
      if self.term.GetAddressOfVersion("source_address", 6):
        saddrs = self.term.GetAddressOfVersion("source_address", 6)
        # Handle ANY source address
        if saddrs[0].with_prefixlen == "::/0":
          saddrs = "ANY"

      # Handle IPv6 destination addresses
      if self.term.GetAddressOfVersion("destination_address", 6):
        daddrs = self.term.GetAddressOfVersion("destination_address", 6)
        if daddrs[0].with_prefixlen == "::/0":
          daddrs = "ANY"

    # Handle IPv4/IPv6 address-family
    elif self.filter_type == "mixed":
      ip_protocol = "IPV4_IPV6"

      # Handle IPv4/IPv6 source addresses
      if self.term.source_address:
        # is there both IPv4 and IPv6 source addresses?
        if self.term.GetAddressOfVersion("source_address", 4) and \
        self.term.GetAddressOfVersion("source_address", 6):
          src_type = 2
          saddrs = self.term.GetAddressOfVersion("source_address", 4) + \
          self.term.GetAddressOfVersion("source_address", 6)
        # is it only IPv4 source?
        elif self.term.GetAddressOfVersion("source_address", 4):
          src_type = 4
          saddrs = self.term.GetAddressOfVersion("source_address", 4)
        # it must be IPv6 only
        else:
          src_type = 6
          saddrs = self.term.GetAddressOfVersion("source_address", 6)
        # Handle ANY source address
        if saddrs[0].with_prefixlen in ("0.0.0.0/0", "::/0"):
          saddrs = "ANY"
          src_type = 2

      # Handle IPv4/IPv6 destination addresses
      if self.term.destination_address:
        # Handle IPv6 only source and no IPv6 destination
        if src_type == 6 and not self.term.GetAddressOfVersion(
        "destination_address", 6
        ):
          # Test if IPv4 destination not ANY
          if self.term.GetAddressOfVersion("destination_address", 4)[0].\
          with_prefixlen != "0.0.0.0/0":
            logging.warning('WARNING: Term %s will not be rendered as it has IPv4/IPv6 '
                            'mismatch for source/destination for mixed address '
                            'family.', self.term.name)
            return None

        # Handle IPv4 only source and no IPv4 destination
        if src_type == 4 and not self.term.GetAddressOfVersion(
          "destination_address", 4
        ):
          # Test if IPv6 destination is defined and not ANY
          if self.term.GetAddressOfVersion("destination_address", 6)[0].\
          with_prefixlen != "::/0":
            logging.warning('WARNING: Term %s will not be rendered as it has IPv4/IPv6 '
                            'mismatch for source/destination for mixed address '
                            'family.', self.term.name)
            return None
        daddrs = self.term.GetAddressOfVersion(
          "destination_address", 4
        ) + self.term.GetAddressOfVersion("destination_address", 6)
        if daddrs[0].with_prefixlen in ("0.0.0.0/0", "::/0"):
          daddrs = "ANY"

    # Convert capirca source addresses into NSX-T JSON policy
    if saddrs:
      # Check the number of source addresses is not over the maximum
      if len(saddrs) > self._MAX_TERM_ITEMS:
        logging.warning('Term %s will not be rendered as the number of '
          'source addresses is over the maximum (%d) supported'
          'by NSX-T', self.term.name, self._MAX_TERM_ITEMS)
        return None

      if saddrs == "ANY":
        source_address = [str(saddrs)]
      else:
        for addr in saddrs:
          if isinstance(addr, (nacaddr.IPv4, nacaddr.IPv6)):
            # Handle CIDR
            if addr.num_addresses > 1:
              source_address.append(f"{addr.with_prefixlen}")
            # Handle single IP
            else:
              source_address.append(f"{addr.network_address}")

    # Convert capirca destination addresses into NSX-T JSON policy
    if daddrs:
      if len(daddrs) > self._MAX_TERM_ITEMS:
        logging.warning('WARNING: Term %s will not be rendered as the number of '
          'destination addresses is over the maximum (%d) supported'
          'by NSX-T', self.term.name, self._MAX_TERM_ITEMS)
        return None
      if daddrs == "ANY":
        destination_address = [str(daddrs)]
      else:
        for addr in daddrs:
          if isinstance(addr, (nacaddr.IPv4, nacaddr.IPv6)):
            # Handle CIDR
            if addr.num_addresses > 1:
              destination_address.append(f"{addr.with_prefixlen}")
            # Handle single IP
            else:
              destination_address.append(f"{addr.network_address}")

    rule = {
      'action': action,
      'resource_type': 'Rule',
      'display_name': name,
      'source_groups': source_address,
      'sources_excluded': sources_excluded,
      'destination_groups': destination_address,
      'destinations_excluded': destinations_excluded,
      # Set mandatory services to ANY, as service_entries will be used
      'services': ['ANY'],
      # Optional parameters not needed and not supported with IP addresses
      # 'profiles': ['ANY'],
      # 'scope': ['ANY'],
      'logged': bool(self.term.logging),
      'description': description,
      'direction': 'IN_OUT',
      'ip_protocol': ip_protocol
    }

    if self.term.protocol:
      icmp_types = []
      services = []
      if self.term.icmp_type:
        icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                             self.term.protocol,
                                             self.filter_type)

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
  SUFFIX = '.nsxt'

  # Maximum number of rules that a NSX-T policy can contain
  _MAX_RULES_PER_POLICY = 1000

  # Warn user when rule count exceeds this number
  _RULECOUNT_WARN_THRESHOLD = 900

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

      filter_type = self._FILTER_OPTIONS_DICT['filter_type']

      applied_to = ''

      #set to store all term names, to check if there're duplicate names
      term_names = set()

      #Term counter to check if we reach the maximum of rules
      cnt_terms = 0

      current_date = datetime.datetime.utcnow().date()
      exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

      new_terms = []
      for term in terms:
        # Check for duplicate term names
        if term.name in term_names:
          raise NsxtDuplicateTermError('There are multiple terms named: %s' %
                                       term.name)
        term_names.add(term.name)

        term.name = self.FixTermLength(term.name)

        # Handle term expiration
        if term.expiration:
          if term.expiration <= current_date:
            logging.warning(
              "WARNING: Term %s is expired and will not be rendered.",
              term.name
            )
          elif term.expiration <= exp_info_date:
            logging.info(
              "INFO: Term %s expires in less than two weeks.",
              term.name
            )

        last_term = Term(term, filter_type, applied_to, self._FILTER_OPTIONS_DICT['verbose'])

        if last_term:
          new_terms.append(last_term)

        cnt_terms += 1

        if cnt_terms > self._RULECOUNT_WARN_THRESHOLD:

          if cnt_terms > self._MAX_RULES_PER_POLICY:
            raise ExceededMaxTermsError(
              "Exceeded maximum number of rules in "
              "a single policy | MAX = ", self._MAX_RULES_PER_POLICY
            )

          logging.warning(
            "Current rule count (%d) is almost at maximum limit of %d",
            cnt_terms, self._MAX_RULES_PER_POLICY
          )

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
    if not 2 <= len(filter_options) <= 6:
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
    verbose = True
    filter_opt_len = len(filter_options)

    if filter_opt_len > 2:
      for index in range(2, filter_opt_len):
        if index == 2 and filter_options[2] != 'securitygroup' and filter_options[2] != 'noVerbose':
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
        elif filter_options[index] == 'noVerbose':
          verbose = False

    self._FILTER_OPTIONS_DICT['section_name'] = section_name
    self._FILTER_OPTIONS_DICT['filter_type'] = filter_type
    self._FILTER_OPTIONS_DICT['section_id'] = section_id
    self._FILTER_OPTIONS_DICT['applied_to'] = applied_to
    self._FILTER_OPTIONS_DICT['verbose'] = verbose


  def __str__(self):
    """Render the output of the nsxt policy."""
    rules = []
    if (len(self.nsxt_policies) > 1):
      raise NsxtUnsupportedManyPolicies('Only one policy can be rendered')
    for (_, _, _, terms) in self.nsxt_policies:
      for term in terms:
          #Catch the case if term is not valid
          try:
            rules = rules + [json.loads(str(term))]
          except:
            continue

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
