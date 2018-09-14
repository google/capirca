# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Google Compute Engine firewall generator.

More information about GCE networking and firewalls:
https://cloud.google.com/compute/docs/networking
https://cloud.google.com/compute/docs/reference/latest/firewalls
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import copy
import datetime
import json
import logging
import re

from capirca.lib import aclgenerator
from six.moves import range


class Error(Exception):
  """Generic error class."""


class GceFirewallError(Error):
  """Raised with problems in formatting for GCE firewall."""


class Term(aclgenerator.Term):
  """Creates the term for the GCE firewall."""

  ACTION_MAP = {'accept': 'allowed',
                'deny': 'denied'}
  # Restrict the number of terms to 256. Proto supports up to 256
  _TERM_ADDRESS_LIMIT = 256

  # Firewall rule name has to match specific RE:
  # The first character must be a lowercase letter, and all following characters
  # must be a dash, lowercase letter, or digit, except the last character, which
  # cannot be a dash.
  # Details: https://cloud.google.com/compute/docs/reference/latest/firewalls
  _TERM_NAME_RE = re.compile(r'^[a-z]([-a-z0-9]*[a-z0-9])?$')

  # Protocols allowed by name from:
  # https://cloud.google.com/vpc/docs/firewalls#protocols_and_ports
  _ALLOW_PROTO_NAME = frozenset(
      ['tcp', 'udp', 'icmp', 'esp', 'ah', 'ipip', 'sctp'])

  # Any protocol not in _ALLOW_PROTO_NAME must be passed by number.
  ALWAYS_PROTO_NUM = set(aclgenerator.Term.PROTO_MAP.keys()) - _ALLOW_PROTO_NAME

  def __init__(self, term):
    super(Term, self).__init__(term)
    self.term = term

    self._validateDirection()
    if self.term.source_address_exclude and not self.term.source_address:
      raise GceFirewallError(
          'GCE firewall does not support address exclusions without a source '
          'address list.')
    if (bool(set(self.term.protocol) - set(['udp', 'tcp']))
        and self.term.destination_port):
      raise GceFirewallError(
          'Only TCP and UDP protocols support destination ports.')
    if (not self.term.source_address and
        not self.term.source_tag) and self.term.direction == 'INGRESS':
      raise GceFirewallError(
          'GCE firewall needs either to specify source address or source tags.')
    if self.term.source_port:
      raise GceFirewallError(
          'GCE firewall does not support source port restrictions.')
    if (self.term.source_address_exclude and self.term.source_address or
        self.term.destination_address_exclude and
        self.term.destination_address):
      self.term.FlattenAll()
      if not self.term.source_address and self.term.direction == 'INGRESS':
        raise GceFirewallError(
            'GCE firewall rule no longer contains any source addresses after '
            'the prefixes in source_address_exclude were removed.')
      if not self.term.destination_address and self.term.direction == 'EGRESS':
        raise GceFirewallError(
            'GCE firewall rule no longer contains any destination addresses '
            'after the prefixes in destination_address_exclude were removed.')

  def __str__(self):
    """Convert term to a string."""
    json.dumps(self.ConvertToDict(), indent=2, separators=(',', ': '))

  def _validateDirection(self):
    if self.term.direction == 'INGRESS':
      if not self.term.source_address and not self.term.source_tag:
        raise GceFirewallError(
            'Ingress rule missing required field oneof "sourceRanges" or '
            '"sourceTags".')

      if self.term.destination_address:
        raise GceFirewallError('Ingress rules cannot include '
                               '"destinationRanges.')

    elif self.term.direction == 'EGRESS':
      if self.term.source_address:
        raise GceFirewallError(
            'Egress rules cannot include "sourceRanges".')

      if not self.term.destination_address:
        raise GceFirewallError(
            'Egress rule missing required field "destinationRanges".')

      if self.term.destination_tag:
        raise GceFirewallError(
            'GCE Egress rule cannot have destination tag.')

  def ConvertToDict(self):
    """Convert term to a dictionary.

    This is used to get a dictionary describing this term which can be
    output easily as a JSON blob.

    Returns:
      A dictionary that contains all fields necessary to create or update a GCE
      firewall.

    Raises:
      GceFirewallError: The term name is too long.
    """
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    term_dict = {
        'description': ' '.join(self.term.comment),
        'name': self.term.name,
        'direction': self.term.direction
        }
    if self.term.network:
      term_dict['network'] = self.term.network
      term_dict['name'] = '%s-%s' % (
          self.term.network.split('/')[-1], term_dict['name'])

    if self.term.source_tag:
      if self.term.direction == 'INGRESS':
        term_dict['sourceTags'] = self.term.source_tag
      elif self.term.direction == 'EGRESS':
        term_dict['targetTags'] = self.term.source_tag
    if self.term.destination_tag and self.term.direction == 'INGRESS':
      term_dict['targetTags'] = self.term.destination_tag
    if self.term.priority:
      term_dict['priority'] = self.term.priority

    rules = []
    saddrs = self.term.GetAddressOfVersion('source_address', 4)
    daddrs = self.term.GetAddressOfVersion('destination_address', 4)

    if not self.term.protocol:
      raise GceFirewallError(
          'GCE firewall rule contains no protocol, it must be specified.')

    proto_dict = copy.deepcopy(term_dict)

    for proto in self.term.protocol:
      dest = {
          'IPProtocol': proto
          }

      if self.term.destination_port:
        ports = dest.setdefault('ports', [])
        for start, end in self.term.destination_port:
          if start == end:
            ports.append(str(start))
          else:
            ports.append('%d-%d' % (start, end))
      action = self.ACTION_MAP[self.term.action[0]]
      if action not in proto_dict:
        proto_dict[action] = []
      proto_dict[self.ACTION_MAP[self.term.action[0]]].append(dest)

    # There's a limit of 256 addresses each term can contain.
    # If we're above that limit, we're breaking it down in more terms.
    if saddrs:
      source_addr_chunks = [
          saddrs[x:x+self._TERM_ADDRESS_LIMIT] for x in range(
              0, len(saddrs), self._TERM_ADDRESS_LIMIT)]
      for i, chunk in enumerate(source_addr_chunks):
        rule = copy.deepcopy(proto_dict)
        if len(source_addr_chunks) > 1:
          rule['name'] = '%s-%d' % (rule['name'], i+1)
        rule['sourceRanges'] = [str(saddr) for saddr in chunk]
        rules.append(rule)
    elif daddrs:
      dest_addr_chunks = [
          daddrs[x:x+self._TERM_ADDRESS_LIMIT] for x in range(
              0, len(daddrs), self._TERM_ADDRESS_LIMIT)]
      for i, chunk in enumerate(dest_addr_chunks):
        rule = copy.deepcopy(proto_dict)
        if len(dest_addr_chunks) > 1:
          rule['name'] = '%s-%d' % (rule['name'], i+1)
        rule['destinationRanges'] = [str(daddr) for daddr in chunk]
        rules.append(rule)
    else:
      rules.append(proto_dict)

    # Sanity checking term name lengths.
    long_rules = [rule['name'] for rule in rules if len(rule['name']) > 63]
    if long_rules:
      raise GceFirewallError(
          'GCE firewall name ended up being too long: %s' % long_rules)
    return rules


class GCE(aclgenerator.ACLGenerator):
  """A GCE firewall policy object."""

  _PLATFORM = 'gce'
  SUFFIX = '.gce'
  _SUPPORTED_AF = set(('inet'))
  # Supported is 63 but we need to account for dynamic updates when the term
  # is rendered (which can add proto and a counter).
  _TERM_MAX_LENGTH = 53
  _GOOD_DIRECTION = ['INGRESS', 'EGRESS']
  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',
                                      'destination_tag',
                                      'source_tag'])

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, _ = super(GCE, self)._BuildTokens()

    # add extra things
    supported_tokens |= {'destination_tag',
                         'expiration',
                         'owner',
                         'priority',
                         'source_tag'}

    # remove unsupported things
    supported_tokens -= {'icmp_type',
                         'platform',
                         'platform_exclude',
                         'verbatim'}
    # easier to make a new structure
    supported_sub_tokens = {'action': {'accept', 'deny'}}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.gce_policies = []

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      network = ''
      direction = 'INGRESS'
      if filter_options:
        for i in self._GOOD_DIRECTION:
          if i in filter_options:
            direction = i
            filter_options.remove(i)

      if filter_options:
        network = filter_options[0]
      else:
        logging.warn('GCE filter does not specify a network.')

      term_names = set()
      for term in terms:
        if term.stateless_reply:
          logging.warn('WARNING: Term %s in policy %s is a stateless reply '
                       'term and will not be rendered.',
                       term.name, filter_name)
          continue
        term.network = network
        if not term.comment:
          term.comment = header.comment
        term.name = self.FixTermLength(term.name)
        if term.name in term_names:
          raise GceFirewallError('Duplicate term name')
        term_names.add(term.name)

        term.direction = direction
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s is expired and '
                         'will not be rendered.', term.name, filter_name)
            continue
        if term.option:
          raise GceFirewallError(
              'GCE firewall does not support term options.')

        self.gce_policies.append(Term(term))

  def __str__(self):
    target = []

    for term in self.gce_policies:
      target.extend(term.ConvertToDict())

    out = '%s\n\n' % (
        json.dumps(target, indent=2, separators=(',', ': '), sort_keys=True))

    return out
