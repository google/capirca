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

import copy
import datetime
import ipaddress
import json
import logging
import re

from typing import Dict, Any

from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from collections import defaultdict
import six


class Error(Exception):
  """Generic error class."""


class OcFirewallError(Error):
  """Raised with problems in formatting for OpenConfig firewall."""


class ExceededAttributeCountError(Error):
  """Raised when the total attribute count of a policy is above the maximum."""


# Graceful handling of dict heierarchy for OpenConfig JSON.
def RecursiveDict():
  return defaultdict(RecursiveDict)


class Term(aclgenerator.Term):
  """Creates the term for the OpenConfig firewall."""

  ACTION_MAP = {'accept': 'ACCEPT',
                'deny': 'DROP',
                'reject': 'REJECT'}

  # OpenConfig ip-protocols always will resolve to an 8-bit int, but these
  # common names are more convenient in a policy file.
  _ALLOW_PROTO_NAME = frozenset(
      ['tcp', 'udp', 'icmp', 'esp', 'ah', 'ipip', 'sctp'])

  AF_RENAME = { 4: 'ipv4',
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
    json.dumps(rules, indent=2)

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

    # Ballot fatigue handling for 'any'.
    saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
    if not saddrs:
      saddrs = ['any']

    daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
    if not daddrs:
      daddrs = ['any']

    sports = self.term.source_port
    if not sports:
      sports = [(0,0)]

    dports = self.term.destination_port
    if not dports:
      dports = [(0,0)]

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
              ace_dict[family]['transport']['config']['source-port'] = int(start)
            else:
              ace_dict[family]['transport']['config']['source-port'] = '%d..%d' % (start, end)

          # Destination Port
          for start, end in dports:
            if not start == end == 0:
              if start == end:
                ace_dict[family]['transport']['config']['destination-port'] = int(start)
              else:
                ace_dict[family]['transport']['config']['destination-port'] = '%d..%d' % (start, end)

            # Protocol
            for proto in protos:
              if isinstance(proto, str):
                if proto != 'none':
                  try:
                    proto_num = self.PROTO_MAP[proto]
                  except KeyError:
                    raise OcFirewallError(
                        'Protocol %s unknown. Use an integer.', proto)
                  ace_dict[family]['config']['protocol'] = proto_num
                rules.append(copy.deepcopy(ace_dict))
              else:
                proto_num = proto
                ace_dict[family]['config']['protocol'] = proto_num
                # This is the business end of ace explosion.
                # A dict is a reference type, so deepcopy is atually required.
                rules.append(copy.deepcopy(ace_dict))

    return rules


class OpenConfig(aclgenerator.ACLGenerator):
  """A OpenConfig firewall policy object."""

  _PLATFORM = 'openconfig'
  SUFFIX = '.oacl'
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    # Remove unsupported things
    supported_tokens -= {'platform',
                         'platform_exclude',
                         'icmp-type',
                         'verbatim'}

    # OpenConfig ACL model only supports these three forwarding actions.
    supported_sub_tokens['action'] = {'accept', 'deny', 'reject'}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.oc_policies = []
    total_rule_count = 0

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      # Options are anything after the platform name in the target message of
      # the policy header, [1:].

      # Get the address family if set.
      address_family = 'inet'
      for i in self._SUPPORTED_AF:
        if i in filter_options:
          address_family = i
          filter_options.remove(i)

      for term in terms:

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue
        # TODO(b/196430344): Add support for options such as
        # established/rst/first-fragment
        if term.option:
          raise OcFirewallError(
              'OpenConfig firewall does not support term options.')

        # Handle mixed for each indvidual term as inet and inet6.
        # inet/inet6 are treated the same.
        term_address_families = []
        if address_family == 'mixed':
          term_address_families = ['inet', 'inet6']
        else:
          term_address_families = [address_family]
        for term_af in term_address_families:
          t = Term(term, term_af)
          for rule in t.ConvertToDict():
            total_rule_count += 1
            self.oc_policies.append(rule)

    logging.info('Total rule count of policy %s is: %d', filter_name,
                 total_rule_count)


  def __str__(self):
    out = '%s\n\n' % (json.dumps(self.oc_policies, indent=2,
                                 separators=(six.ensure_str(','),
                                             six.ensure_str(': ')),
                                 sort_keys=True))

    return out
