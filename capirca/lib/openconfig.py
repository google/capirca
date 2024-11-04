# Copyright 2021 Google Inc. All Rights Reserved.
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

"""Openconfig yang ACL generator.

More information about the Openconfig ACL model schema:
http://ops.openconfig.net/branches/models/master/openconfig-acl.html
"""

import collections
import copy
import datetime
import json
import logging

from capirca.lib import aclgenerator
import six


class Error(Exception):
  """Generic error class."""


class OcFirewallError(Error):
  """Raised with problems in formatting for OpenConfig firewall."""


class ExceededAttributeCountError(Error):
  """Raised when the total attribute count of a policy is above the maximum."""


# Graceful handling of dict heierarchy for OpenConfig JSON.
def RecursiveDict():
  return collections.defaultdict(RecursiveDict)


class Term(aclgenerator.Term):
  """Creates the term for the OpenConfig firewall."""

  ACTION_MAP = {'accept': 'ACCEPT', 'deny': 'DROP', 'reject': 'REJECT'}

  # OpenConfig ip-protocols always will resolve to an 8-bit int, but these
  # common names are more convenient in a policy file.
  _ALLOW_PROTO_NAME = frozenset(
      ['tcp', 'udp', 'icmp', 'esp', 'ah', 'ipip', 'sctp']
  )

  AF_RENAME = {
      4: 'ipv4',
      6: 'ipv6',
  }

  def __init__(self, term, inet_version='inet'):
    super().__init__(term)
    self.term = term
    self.inet_version = inet_version

    # Combine (flatten) addresses with their exclusions into a resulting
    # flattened_saddr, flattened_daddr, flattened_addr.
    self.term.FlattenAll()

  def __str__(self):
    """Convert term to a string."""
    rules = self.ConvertToDict()
    return json.dumps(rules, indent=2)

  def ConvertToDict(self):
    """Convert term to a dictionary.

    This is used to get a dictionary describing this term which can be
    output easily as an Openconfig JSON blob. It represents an "acl-entry"
    message from the OpenConfig ACL schema.

    Returns:
      A list of dictionaries that contains all fields necessary to create or
      update a OpenConfig acl-entry.
    """
    term_dict = RecursiveDict()

    # Rules will hold all exploded acl-entry dictionaries.
    rules = []

    # Convert the integer to the proper openconfig schema name str, ipv4/ipv6.
    term_af = self.AF_MAP.get(self.inet_version)
    family = self.AF_RENAME[term_af]

    # Action
    action = self.ACTION_MAP[self.term.action[0]]
    term_dict['actions'] = {}
    term_dict['actions']['config'] = {}
    term_dict['actions']['config']['forwarding-action'] = action

    desc = f'[{self.term.name}]: {" ".join(self.term.comment)}'
    term_dict['config']['description'] = desc

    # Ballot fatigue handling for 'any'.
    saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
    if not saddrs:
      saddrs = ['any']

    daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
    if not daddrs:
      daddrs = ['any']

    sports = self.term.source_port
    if not sports:
      sports = [(0, 0)]

    dports = self.term.destination_port
    if not dports:
      dports = [(0, 0)]

    protos = self.term.protocol
    if not protos:
      protos = ['none']

    ace_dict = copy.deepcopy(term_dict)
    # Source Addresses
    for saddr in saddrs:
      if saddr != 'any':
        ace_dict[family]['config']['source-address'] = str(saddr)

      # Destination Addresses
      for daddr in daddrs:
        if daddr != 'any':
          ace_dict[family]['config']['destination-address'] = str(daddr)

        # Source Port
        for start, end in sports:
          # 'any' starts and ends with zero.
          if not start == end == 0:
            if start == end:
              ace_dict['transport']['config']['source-port'] = int(start)
            else:
              ace_dict['transport']['config']['source-port'] = '%d..%d' % (
                  start,
                  end,
              )

          # Destination Port
          for start, end in dports:
            if not start == end == 0:
              if start == end:
                ace_dict['transport']['config']['destination-port'] = int(start)
              else:
                ace_dict['transport']['config']['destination-port'] = (
                    '%d..%d' % (start, end)
                )

            # Protocol
            for proto in protos:
              if isinstance(proto, str):
                if proto != 'none':
                  try:
                    proto_num = self.PROTO_MAP[proto]
                  except KeyError as e:
                    raise OcFirewallError(
                        f'Protocol {proto} unknown. Use an integer.'
                    ) from e
                  ace_dict[family]['config']['protocol'] = proto_num
                rule_dict = copy.deepcopy(ace_dict)
              else:
                proto_num = proto
                ace_dict[family]['config']['protocol'] = proto_num
                # This is the business end of ace explosion.
                # A dict is a reference type, so deepcopy is atually required.
                rule_dict = copy.deepcopy(ace_dict)

              # options
              for opt in self.term.option:
                if opt == 'tcp-established' and proto != 'udp':
                  rule_dict['transport']['config']['detail-mode'] = 'BUILTIN'
                  rule_dict['transport']['config'][
                      'builtin-detail'
                  ] = 'TCP_ESTABLISHED'
                if opt == 'established' and proto != 'udp':
                  rule_dict['transport']['config']['detail-mode'] = 'BUILTIN'
                  rule_dict['transport']['config'][
                      'builtin-detail'
                  ] = 'TCP_ESTABLISHED'
                # initial only for tcp
                if opt == 'initial' and proto == 'tcp':
                  rule_dict['transport']['config']['detail-mode'] = 'BUILTIN'
                  rule_dict['transport']['config'][
                      'builtin-detail'
                  ] = 'TCP_INITIAL'
                # is-fragment only for ipv4
                if opt == 'is-fragment' and term_af == 4:
                  rule_dict['transport']['config']['detail-mode'] = 'BUILTIN'
                  rule_dict['transport']['config'][
                      'builtin-detail'
                  ] = 'FRAGMENT'
              rules.append(rule_dict)

    return rules


class OpenConfig(aclgenerator.ACLGenerator):
  """A OpenConfig firewall policy object."""

  _PLATFORM = 'openconfig'
  SUFFIX = '.oacl'
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
  OC_AF_TYPE = {'inet': 'ACL_IPV4', 'inet6': 'ACL_IPV6'}

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    # Remove unsupported things
    supported_tokens -= {'icmp-type',
                         'verbatim'}

    # OpenConfig ACL model only supports these three forwarding actions.
    supported_sub_tokens['action'] = {'accept', 'deny', 'reject'}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    acl_sets = []
    sequence_id = 0

    current_date = datetime.datetime.now(datetime.UTC).date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      # Options are anything after the platform name in the target message of
      # the policy header, [1:].

      # Get the address family if set.
      address_family = 'inet'
      for i in self._SUPPORTED_AF:
        if i in filter_options:
          address_family = i
          filter_options.remove(i)
      # Handle mixed for each indvidual term as inet and inet6.
      # inet/inet6 are treated the same.
      term_address_families = [address_family]
      if address_family == 'mixed':
        term_address_families = ['inet', 'inet6']

      for term_af in term_address_families:
        acl_set = RecursiveDict()
        filter_name = header.FilterName(self._PLATFORM)
        # If mixed filter_type, will append 4 or 6 to the filter name
        if address_family == 'mixed':
          suffix = '4' if term_af == 'inet' else '6'
          filter_name = f'{filter_name}{suffix}'
        acl_set['name'] = filter_name
        acl_set['type'] = self.OC_AF_TYPE[term_af]
        acl_set['config']['name'] = filter_name
        acl_set['config']['type'] = self.OC_AF_TYPE[term_af]

        oc_policies = []
        for term in terms:
          if term.platform_exclude:
            if self._PLATFORM in term.platform_exclude:
              continue

          if term.platform:
            if self._PLATFORM not in term.platform:
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
          for opt in term.option:
            if opt in ['first-fragment', 'sample', 'rst']:
              raise OcFirewallError(
                  'OpenConfig firewall does not support term option %s.' % opt
              )

          t = Term(term, term_af)
          for rule in t.ConvertToDict():
            sequence_id += 1
            rule['sequence-id'] = sequence_id
            rule['config']['sequence-id'] = sequence_id
            oc_policies.append(rule)

        acl_set['acl-entries']['acl-entry'] = oc_policies
        acl_sets.append(acl_set)

        logging.info(
            'Total rule count of policy %s is: %d',
            filter_name,
            len(oc_policies),
        )
    self.acl_data = {'acl-sets': {'acl-set': acl_sets}}

  def __str__(self):
    out = '%s\n\n' % (
        json.dumps(
            self.acl_data,
            indent=2,
            separators=(six.ensure_str(','), six.ensure_str(': ')),
            sort_keys=True,
        )
    )

    return out
