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
"""Kubernetes NetworkPolicy resource generator.

More information about Kubernetes NetworkPolicy:
https://kubernetes.io/docs/concepts/services-networking/network-policies/
https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/
"""

import copy
import datetime
import logging
import re

from capirca.lib import aclgenerator
import yaml


class Error(Exception):
  """Generic error class."""


class K8sNetworkPolicyError(Error):
  """Raised with problems in formatting for Kubernetes NetworkPolicies."""


class ExceededAttributeCountError(Error):
  """Raised when the total attribute count of a policy is above the maximum."""


def IsDefaultDeny(term):
  """Returns true if a term is a default deny without IPs, ports, etc."""
  skip_attrs = [
      'flattened', 'flattened_addr', 'flattened_saddr', 'flattened_daddr',
      'action', 'comment', 'name', 'logging', 'direction'
  ]
  if 'deny' not in term.action:
    return False
  # This lc will look through all methods and attributes of the object.
  # It returns only the attributes that need to be looked at to determine if
  # this is a default deny.
  for i in [
      a for a in dir(term) if not a.startswith('__') and a.islower() and
      not callable(getattr(term, a))
  ]:
    if i in skip_attrs:
      continue
    v = getattr(term, i)
    if isinstance(v, str) and v:
      return False
    if isinstance(v, list) and v:
      return False

  return True


def GetNextPriority(priority):
  """Get the priority for the next rule."""
  return priority


class Term(aclgenerator.Term):
  """Creates the term for the Kubernetes NetworkPolicy."""

  _API_VERSION = 'networking.k8s.io/v1'
  _RESOURCE_KIND = 'NetworkPolicy'
  # Policy rule name has to match specific RE:
  # No more than 253 characters, beginning and ending
  # with a lowercase alphanumeric character with dashes, dots, and lowercase
  # alphanumerics between.
  # Details: https://kubernetes.io/docs/concepts/overview/working-with-objects/names
  _TERM_NAME_RE = re.compile(r'^[a-z0-9]([a-z0-9-\.]){0,251}[a-z0-9]$')
  _TERM_MAX_LENGTH = 253

  # Protocols allowed are only tcp/udp/sctp
  # https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.23/#networkpolicyport-v1-networking-k8s-io
  PROTO_MAP = {
      'tcp': 6,
      'udp': 17,
      'sctp': 132,
      'all': -1,  # Used for default deny
  }

  def __init__(self, term):
    super().__init__(term)
    self.term = term

    if 'deny' in self.term.action:
      if IsDefaultDeny(term):
        return
      else:
        raise K8sNetworkPolicyError(
            'Kubernetes NetworkPolicy does not support explicit deny terms.')

    self._validateDirection()

    if self.term.source_port:
      raise K8sNetworkPolicyError(
          'Kubernetes NetworkPolicy does not support source port restrictions.')

    # Raise an error if the flattening of address exclusions would result in
    # overly broad network access control policies
    if (self.term.source_address_exclude and self.term.source_address or
        self.term.destination_address_exclude and
        self.term.destination_address):
      self.term.FlattenAll(mutate=False)
      if not self.term.flattened_saddr and self.term.direction == 'INGRESS':
        logging.error(
            'Kubernetes NetworkPolicy term %s no longer contains any source '
            'addresses after the prefixes in source_address_exclude were '
            'removed. Not rendering term.', self.term.name)
        self.term = None
        return

      if not self.term.flattened_daddr and self.term.direction == 'EGRESS':
        logging.error(
            'Kubernetes NetworkPolicy term %s no longer contains any destination '
            'addresses after the prefixes in destination_address_exclude were '
            'removed. Not rendering term.', self.term.name)
        self.term = None
        return

  def __str__(self):
    """Convert term to a string."""
    return yaml.safe_dump(self.ConvertToDict())

  def _validateDirection(self):
    if self.term.direction == 'INGRESS':
      if not self.term.source_address:
        raise K8sNetworkPolicyError(
            'Ingress rule missing required field "source-address"')

      if self.term.destination_address:
        raise K8sNetworkPolicyError('Ingress rules cannot include '
                                    '"destination-address.')

    elif self.term.direction == 'EGRESS':
      if self.term.source_address:
        raise K8sNetworkPolicyError(
            'Egress rules cannot include "source-address".')

      if not self.term.destination_address:
        raise K8sNetworkPolicyError(
            'Egress rule missing required field "destination-address".')

  def ConvertToDict(self):
    """Convert term to a dictionary.

    This is used to get a dictionary describing this term which can be
    output easily as a YAML object.

    Returns:
      A dictionary that contains a complete Kubernetes NetworkPolicy resource

    Raises:
      K8sNetworkPolicyError: The term name is not valid.
    """
    if not self.term:
      return {}

    if not self._TERM_NAME_RE.match(self.term.name):
      raise K8sNetworkPolicyError(
          'Term name %s is not valid. See https://kubernetes.io/docs/concepts/overview/working-with-objects/names for more information'
          % (self.term.name))

    resource_dict = {
        'apiVersion': self._API_VERSION,
        'kind': self._RESOURCE_KIND,
        'metadata': {
            'name': self.term.name,
            'annotations': {},
        },
        'spec': {
            'podSelector': {},
            'policyTypes': [self.term.direction.capitalize()]
        },
    }

    if self.term.comment:
      resource_dict['metadata']['annotations']['comment'] = ' '.join(
          self.term.comment)
    if self.term.owner:
      resource_dict['metadata']['annotations']['owner'] = self.term.owner

    # We only allow one kind of deny policy, and thats a default deny. Because
    # of that, we can quickly return an empty policy in the specified direction
    if 'deny' in self.term.action:
      return resource_dict

    peer_selectors = []
    peer_selector_key = ''
    base_port_selector = {}
    if self.term.direction == 'INGRESS':
      for source_address in self.term.source_address:
        peer_selector = {'ipBlock': {'cidr': str(source_address)}}
        for exclude in self.term.source_address_exclude:
          if peer_selector['ipBlock'].get('except') is None:
            peer_selector['ipBlock']['except'] = []

          peer_selector['ipBlock']['except'].append(str(exclude))
        peer_selectors.append(peer_selector)
      peer_selector_key = 'from'
    else:
      for destination_address in self.term.destination_address:
        peer_selector = {'ipBlock': {'cidr': str(destination_address)}}
        for exclude in self.term.destination_address_exclude:
          if peer_selector['ipBlock'].get('except') is None:
            peer_selector['ipBlock']['except'] = []

          peer_selector['ipBlock']['except'].append(str(exclude))
        peer_selectors.append(peer_selector)
      peer_selector_key = 'to'

    # Build a base port selector list from ports
    base_port_selectors = []
    for start, end in self.term.destination_port:
      if start == end:
        base_port_selector = {'port': start}
      else:
        base_port_selector = {'port': start, 'endPort': end}

      base_port_selectors.append(base_port_selector)

    # Use the ports info to make one selector per port pair per proto
    port_selectors = []
    for proto in self.term.protocol:

      # If the list of ports is null, we still need to specify proto
      if not base_port_selectors:
        port_selectors.append({'protocol': proto.upper()})
        continue

      for base_selector in base_port_selectors:
        current_selector = copy.deepcopy(base_selector)
        # NetworkPolicies require uppercased proto name
        current_selector['protocol'] = proto.upper()
        port_selectors.append(current_selector)

    resource_dict['spec'][self.term.direction.lower()] = [{
        'ports': port_selectors,
        peer_selector_key: peer_selectors,
    }]

    return resource_dict


class K8s(aclgenerator.ACLGenerator):
  """A Kubernetes NetworkPolicy object."""

  _API_VERSION = 'networking.k8s.io/v1'
  _RESOURCE_KIND = 'NetworkPolicyList'
  _PLATFORM = 'k8s'
  SUFFIX = '.yml'
  _SUPPORTED_AF = frozenset(('mixed'))
  _GOOD_DIRECTION = ['INGRESS', 'EGRESS']
  _OPTIONAL_SUPPORTED_KEYWORDS = frozenset(['expiration'])

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, _ = super()._BuildTokens()

    # add extra things
    supported_tokens |= {'expiration', 'owner'}

    # remove unsupported things
    supported_tokens -= {'icmp_type', 'source-port', 'verbatim'}
    # easier to make a new structure
    supported_sub_tokens = {'action': {'accept', 'deny'}}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.network_policies = []
    total_rule_count = 0

    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      direction = 'INGRESS'
      if filter_options:
        for i in self._GOOD_DIRECTION:
          if i in filter_options:
            direction = i
            filter_options.remove(i)

      term_names = set()
      for term in terms:
        if term.stateless_reply:
          logging.warning(
              'WARNING: Term %s in policy %s is a stateless reply '
              'term and will not be rendered.', term.name, filter_name)
          continue
        if not term.comment:
          term.comment = header.comment
        if direction == 'EGRESS':
          term.name += '-e'
        term.name = self.FixTermLength(term.name)
        if term.name in term_names:
          raise K8sNetworkPolicyError('Duplicate term name %s' % term.name)
        term_names.add(term.name)

        term.direction = direction
        if term.expiration:
          if term.expiration <= current_date:
            logging.warning(
                'WARNING: Term %s in policy %s is expired and '
                'will not be rendered.', term.name, filter_name)
            continue
          if term.expiration <= exp_info_date:
            logging.info(
                'INFO: Term %s in policy %s expires '
                'in less than two weeks.', term.name, filter_name)
        if term.option:
          raise K8sNetworkPolicyError(
              'Kubernetes NetworkPolicy does not support term options.')

        # Only generate the term if it's for the appropriate platform
        if term.platform:
          if self._PLATFORM not in term.platform:
            continue
        if term.platform_exclude:
          if self._PLATFORM in term.platform_exclude:
            continue

        term_dict = Term(term).ConvertToDict()
        if term_dict:
          total_rule_count += 1
          self.network_policies.append(term_dict)

    logging.info('Total rule count of policy %s is: %d', filter_name,
                 total_rule_count)

  def __str__(self):
    if not self.network_policies:
      return ''
    list_resource = {
        'apiVersion': self._API_VERSION,
        'kind': self._RESOURCE_KIND,
        'items': self.network_policies,
    }
    return yaml.safe_dump(list_resource)
