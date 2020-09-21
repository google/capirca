"""Google Cloud Hierarchical Firewall Generator.

Hierarchical Firewalls (HF) are represented in a SecurityPolicy GCP resouce.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

from typing import Dict, Text, Any

from absl import logging
from capirca.lib import gcp
from capirca.lib import nacaddr


class ExceededCostError(gcp.Error):
  """Raised when the total cost of a policy is above the maximum."""


class DifferentPolicyNameError(gcp.Error):
  """Raised when headers in the same policy have a different policy name."""


class Term(gcp.Term):
  """Used to create an individual term."""

  ACTION_MAP = {'accept': 'allow', 'next': 'goto_next'}

  _MAX_TERM_COMMENT_LENGTH = 64

  _PROTO_NAMES = ['tcp', 'udp', 'icmp', 'icmpv6', 'esp', 'ah', 'sctp']

  def __init__(self, term, address_family='inet'):
    super(Term, self).__init__(term)
    self.address_family = address_family
    self.term = term
    self.skip = False
    self._ValidateTerm()

    # Don't render icmp protocol terms under inet6.
    if self.address_family == 'inet6':
      if ['icmp'] == self.term.protocol:
        # Skip term if its only protocol is icmp to prevent an empty list,
        # which is equivalent to any protocol.
        self.skip = True
      elif 'icmp' in self.term.protocol:
        self.term.protocol.remove('icmp')

    # Don't render icmpv6 protocol terms under inet.
    if self.address_family == 'inet':
      # Skip term if its only protocol is icmpv6 to prevent an empty list,
      # which is equivalent to any protocol.
      if ['icmpv6'] == self.term.protocol:
        self.skip = True
      elif 'icmpv6' in self.term.protocol:
        self.term.protocol.remove('icmpv6')

  def _ValidateTerm(self):
    if self.term.destination_tag or self.term.source_tag:
      raise gcp.TermError('Hierarchical Firewall does not support tags')

    if self.term.protocol:
      for protocol in self.term.protocol:
        if protocol not in self._PROTO_NAMES:
          raise gcp.TermError('Protocol %s is not supported' % protocol)

    for proj, vpc in self.term.target_resources:
      if not gcp.IsProjectIDValid(proj):
        raise gcp.TermError(
            'Project ID "%s" must be 6 to 30 lowercase letters, digits, or hyphens.'
            ' It must start with a letter. Trailing hyphens are prohibited.' %
            proj)
      if not gcp.IsVPCNameValid(vpc):
        raise gcp.TermError('VPC name "%s" must start with a lowercase letter '
                            'followed by up to 62 lowercase letters, numbers, '
                            'or hyphens, and cannot end with a hyphen.' % vpc)
    if self.term.source_port:
      raise gcp.TermError('Hierarchical firewall does not support source port '
                          'restrictions.')
    if self.term.option:
      raise gcp.TermError('Hierarchical firewall does not support the '
                          'TCP_ESTABLISHED option.')

  def ConvertToDict(self, priority_index):
    """Converts term to dict representation of SecurityPolicy.Rule JSON format.

    Takes all of the attributes associated with a term (match, action, etc) and
    converts them into a dictionary which most closely represents
    the SecurityPolicy.Rule JSON format.

    Args:
      priority_index: An integer priority value assigned to the term.

    Returns:
      A dict term.
    """
    if self.skip:
      return {}

    term_dict = {
        'action': self.ACTION_MAP.get(self.term.action[0], self.term.action[0]),
        'direction': self.term.direction,
        'priority': priority_index
    }

    target_resources = []
    for proj, vpc in self.term.target_resources:
      target_resources.append('projects/{}/networks/{}'.format(proj, vpc))

    if target_resources:  # Only set when non-empty.
      term_dict['targetResources'] = target_resources

    term_dict['enableLogging'] = self._GetLoggingSetting()

    # This combo provides ability to identify the rule.
    raw_descirption = self.term.name + ': ' + ' '.join(self.term.comment)
    term_dict['description'] = gcp.TruncateString(raw_descirption,
                                                  self._MAX_TERM_COMMENT_LENGTH)

    ip_version = self.AF_MAP[self.address_family]
    if ip_version == 4:
      any_ip = [nacaddr.IP('0.0.0.0/0')]
    else:
      any_ip = [nacaddr.IPv6('::/0')]

    if self.term.direction == 'EGRESS':
      daddrs = self.term.GetAddressOfVersion('destination_address', ip_version)
      if not daddrs:
        daddrs = any_ip
      term_dict['match'] = {
          'config': {
              'destIpRanges': [daddr.with_prefixlen for daddr in daddrs]
          }
      }
    else:
      saddrs = self.term.GetAddressOfVersion('source_address', ip_version)
      if not saddrs:
        saddrs = any_ip
      term_dict['match'] = {
          'config': {
              'srcIpRanges': [saddr.with_prefixlen for saddr in saddrs]
          }
      }

    protocols_and_ports = []
    if not self.term.protocol:
      # Empty protocol list means any protocol, but any protocol in HF is
      # represented as "all"
      protocols_and_ports = [{'ipProtocol': 'all'}]
    else:
      for proto in self.term.protocol:
        proto_ports = {'ipProtocol': proto}
        if self.term.destination_port:
          ports = self._GetPorts()
          if ports:  # Only set when non-empty.
            proto_ports['ports'] = ports
        protocols_and_ports.append(proto_ports)

    term_dict['match']['config']['layer4Configs'] = protocols_and_ports

    # match needs a field called versionedExpr with value FIREWALL
    # See documentation:
    # https://cloud.google.com/compute/docs/reference/rest/beta/organizationSecurityPolicies/addRule
    term_dict['match']['versionedExpr'] = 'FIREWALL'

    return term_dict

  def __str__(self):
    return ''


class HierarchicalFirewall(gcp.GCP):
  """A GCP Hierarchical Firewall policy."""

  SUFFIX = '.gcphf'
  _ANY = [nacaddr.IP('0.0.0.0/0')]
  _PLATFORM = 'gcp_hf'
  _SUPPORTED_AF = frozenset(['inet'])
  _DEFAULT_MAXIMUM_COST = 100

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      Tuple containing both supported tokens and sub tokens.
    """
    supported_tokens, _ = super(HierarchicalFirewall, self)._BuildTokens()

    supported_tokens |= {
        'destination_tag', 'expiration', 'source_tag', 'translated',
        'target_resources', 'logging'
    }

    supported_tokens -= {
        'destination_address_exclude', 'expiration', 'icmp_type', 'platform',
        'platform_exclude', 'source_address_exclude', 'verbatim'
    }

    supported_sub_tokens = {'action': {'accept', 'deny', 'next'}}
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Translates a Capirca policy into a HF-specific data structure.

    Takes in a POL file, parses each term and populates the policy
    dict. Each term in this list is a dictionary formatted according to
    HF's rule API specification.  Additionally, checks for its quota.

    Args:
      pol: A Policy() object representing a given POL file.
      exp_info: An int that specifies number of weeks until policy expiry.

    Raises:
      ExceededCostError: Raised when the cost of a policy exceeds the default
          maximum cost.
      HeaderError: Raised when the header cannot be parsed or a header option is
          invalid.
      DifferentPolicyNameError: Raised when a header policy name differs from
          other in the same policy.
    """
    self.policies = []
    policy = {
        'rules': [],
        'type': 'FIREWALL'
    }
    is_policy_modified = False
    counter = 1
    total_cost = 0
    for header, terms in pol.filters:

      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      is_policy_modified = True

      # Get term direction if set.
      direction = 'INGRESS'
      for i in self._GOOD_DIRECTION:
        if i in filter_options:
          direction = i
          filter_options.remove(i)

      # Get the address family if set.
      address_family = 'inet'
      for i in self._SUPPORTED_AF:
        if i in filter_options:
          address_family = i
          filter_options.remove(i)

      # Find the default maximum cost of a policy, an integer, if specified.
      max_cost = self._DEFAULT_MAXIMUM_COST
      for opt in filter_options:
        try:
          max_cost = int(opt)
          filter_options.remove(opt)
          break
        except ValueError:
          continue

      if max_cost > 65536:
        raise gcp.HeaderError(
            'Default maximum cost cannot be higher than 65536')

      # Get policy name and validate it to meet displayName requirements.
      policy_name = header.FilterName(self._PLATFORM)
      if not policy_name:
        raise gcp.HeaderError(
            'Policy name was not specified in header')
      filter_options.remove(policy_name)
      if len(policy_name) > 63:
        raise gcp.HeaderError(
            'Policy name "%s" is too long; the maximum number of characters '
            'allowed is 63' % (policy_name))
      if not bool(re.match('^[a-z]([-a-z0-9]*[a-z0-9])?$', policy_name)):
        raise gcp.HeaderError(
            'Invalid string for displayName, "%s"; the first character must be '
            'a lowercase letter, and all following characters must be a dash, '
            'lowercase letter, or digit, except the last character, which '
            'cannot be a dash.' % (policy_name))
      if 'displayName' in policy and policy['displayName'] != policy_name:
        raise DifferentPolicyNameError(
            'Policy names that are from the same policy are expected to be '
            'equal, but %s is different to %s' %
            (policy['displayName'], policy_name))
      policy['displayName'] = policy_name

      # If there are remaining options, they are unknown/unsupported options.
      if filter_options:
        raise gcp.HeaderError(
            'Unsupported or unknown filter options %s in policy %s ' %
            (str(filter_options), policy_name))

      for term in terms:
        if term.stateless_reply:
          continue

        if gcp.IsDefaultDeny(term):
          if direction == 'EGRESS':
            term.destination_address = self._ANY
          else:
            term.source_address = self._ANY
        term.name = self.FixTermLength(term.name)
        term.direction = direction
        dict_term = Term(
            term,
            address_family=address_family).ConvertToDict(priority_index=counter)
        counter += 1
        total_cost += GetCost(dict_term)

        if total_cost > max_cost:
          raise ExceededCostError('Policy cost (%d) for %s reached the maximum '
                                  '(%d)' % (total_cost, policy['displayName'],
                                            max_cost))
        policy['rules'].append(dict_term)

    self.policies.append(policy)

    # Do not render an empty rules if no policies have been evaluated.
    if not is_policy_modified:
      self.policies = []

    if total_cost > 0:
      logging.info('Policy %s quota cost: %d',
                   policy['displayName'], total_cost)


def GetCost(dict_term: Dict[Text, Any]):
  """Calculate the cost of a term in its dictionary form.

  Quota is charged based on how complex the rules are rather than simply
  limiting the number of rules.

  A firewall rule tuple is the unique combination of IP range, protocol, and
  port defined as a matching condition in a firewall rule. And the cost of a
  firewall rule tuple is the total number of elements within it.

  Note: The goal of this function is not to determine if a term is valid, but
      to calculate its cost/quota regardless of correctness.

  Args:
    dict_term: A dict object.

  Returns:
    int: The cost of the term.
  """
  config = dict_term.get('match', {}).get('config', {})

  addresses = (len(config.get('destIpRanges', []))
               or len(config.get('srcIpRanges', [])))
  proto_ports = 0

  for l4config in config.get('layer4Configs', []):
    proto_ports += len(l4config.get('ports', [])) or 1

  return (addresses or 1) * (proto_ports or 1)
