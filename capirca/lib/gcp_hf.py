"""Google Cloud Hierarchical Firewall Generator.

Hierarchical Firewalls (HF) are represented in a SecurityPolicy GCP resouce.
"""

import copy
import re

from typing import Dict, Any

from absl import logging
from capirca.lib import gcp
from capirca.lib import nacaddr


class ExceededCostError(gcp.Error):
  """Raised when the total cost of a policy is above the maximum."""


class DifferentPolicyNameError(gcp.Error):
  """Raised when headers in the same policy have a different policy name."""


class ApiVersionSyntaxMap:
  """Defines the syntax changes between different API versions.

   http://cloud/compute/docs/reference/rest/v1/firewallPolicies/addRule
   http://cloud/compute/docs/reference/rest/beta/organizationSecurityPolicies/addRule
  """
  SYNTAX_MAP = {
      'beta': {
          'display_name': 'displayName',
          'dest_ip_range': 'destIpRanges',
          'src_ip_range': 'srcIpRanges',
          'layer_4_config': 'layer4Configs'
      },
      'ga': {
          'display_name': 'shortName',
          'dest_ip_range': 'destIpRanges',
          'src_ip_range': 'srcIpRanges',
          'layer_4_config': 'layer4Configs'
      }
  }


class Term(gcp.Term):
  """Used to create an individual term."""

  ACTION_MAP = {'accept': 'allow', 'next': 'goto_next'}

  _MAX_TERM_COMMENT_LENGTH = 64

  _TARGET_RESOURCE_FORMAT = 'https://www.googleapis.com/compute/v1/projects/{}/global/networks/{}'

  _TERM_ADDRESS_LIMIT = 256

  _TERM_TARGET_RESOURCES_LIMIT = 256

  _TERM_DESTINATION_PORTS_LIMIT = 256

  def __init__(self,
               term,
               address_family='inet',
               policy_inet_version='inet',
               api_version='beta'):
    super().__init__(term)
    self.address_family = address_family
    self.term = term
    self.skip = False
    self._ValidateTerm()
    self.api_version = api_version

    # This is to handle mixed, where the policy_inet_version is mixed,
    # but the term inet version is either inet/inet6.
    # This is only useful for term name and priority.
    self.policy_inet_version = policy_inet_version

  def _ValidateTerm(self):
    if self.term.destination_tag or self.term.source_tag:
      raise gcp.TermError('Hierarchical Firewall does not support tags')

    if len(self.term.target_resources) > self._TERM_TARGET_RESOURCES_LIMIT:
      raise gcp.TermError(
          'Term: %s  target_resources field contains %s resources. It should not contain more than "%s".'
          % (self.term.name, str(len(
              self.term.target_resources)), self._TERM_TARGET_RESOURCES_LIMIT))

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

    if len(self.term.destination_port) > self._TERM_DESTINATION_PORTS_LIMIT:
      raise gcp.TermError(
          'Term: %s destination_port field contains %s ports. It should not contain more than "%s".'
          % (self.term.name, str(len(
              self.term.destination_port)), self._TERM_DESTINATION_PORTS_LIMIT))

    # Since policy_inet_version is used to handle 'mixed'.
    # We should error out if the individual term's inet version (address_family)
    # is anything other than inet/inet6, since this should never happen
    # naturally. Something has gone horribly wrong if you encounter this error.
    if self.address_family == 'mixed':
      raise gcp.TermError(
          'Hierarchical firewall rule has incorrect inet_version for rule: %s' %
          self.term.name)

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

    rules = []

    # Identify if this is inet6 processing for a term under a mixed policy.
    mixed_policy_inet6_term = False
    if self.policy_inet_version == 'mixed' and self.address_family == 'inet6':
      mixed_policy_inet6_term = True

    term_dict = {
        'action': self.ACTION_MAP.get(self.term.action[0], self.term.action[0]),
        'direction': self.term.direction,
        'priority': priority_index
    }

    # Get the correct syntax for API versions.
    src_ip_range = ApiVersionSyntaxMap.SYNTAX_MAP[
        self.api_version]['src_ip_range']
    dest_ip_range = ApiVersionSyntaxMap.SYNTAX_MAP[
        self.api_version]['dest_ip_range']
    layer_4_config = ApiVersionSyntaxMap.SYNTAX_MAP[
        self.api_version]['layer_4_config']

    target_resources = []
    for proj, vpc in self.term.target_resources:
      target_resources.append(self._TARGET_RESOURCE_FORMAT.format(proj, vpc))

    if target_resources:  # Only set when non-empty.
      term_dict['targetResources'] = target_resources

    term_dict['enableLogging'] = self._GetLoggingSetting()

    # This combo provides ability to identify the rule.
    term_name = self.term.name
    if mixed_policy_inet6_term:
      term_name = gcp.GetIpv6TermName(term_name)
    raw_description = term_name + ': ' + ' '.join(self.term.comment)
    term_dict['description'] = gcp.TruncateString(raw_description,
                                                  self._MAX_TERM_COMMENT_LENGTH)

    filtered_protocols = []
    for proto in self.term.protocol:
      # ICMP filtering by inet_version
      # Since each term has inet_version, 'mixed' is correctly processed here.
      if proto == 'icmp' and self.address_family == 'inet6':
        logging.warning(
            'WARNING: Term %s is being rendered for inet6, ICMP '
            'protocol will not be rendered.', self.term.name)
        continue
      if proto == 'icmpv6' and self.address_family == 'inet':
        logging.warning(
            'WARNING: Term %s is being rendered for inet, ICMPv6 '
            'protocol will not be rendered.', self.term.name)
        continue
      if proto == 'igmp' and self.address_family == 'inet6':
        logging.warning(
            'WARNING: Term %s is being rendered for inet6, IGMP '
            'protocol will not be rendered.', self.term.name)
        continue
      filtered_protocols.append(proto)
    # If there is no protocol left after ICMP/IGMP filtering, drop this term.
    # But only do this for terms that originally had protocols.
    # Otherwise you end up dropping the default-deny.
    if self.term.protocol and not filtered_protocols:
      return {}

    protocols_and_ports = []
    if not self.term.protocol:
      # Empty protocol list means any protocol, but any protocol in HF is
      # represented as "all"
      protocols_and_ports = [{'ipProtocol': 'all'}]
    else:
      for proto in filtered_protocols:
        # If the protocol name is not supported, use the protocol number.
        if proto not in self._ALLOW_PROTO_NAME:
          proto = str(self.PROTO_MAP[proto])
          logging.info('INFO: Term %s is being rendered using protocol number',
                       self.term.name)
        proto_ports = {'ipProtocol': proto}
        if self.term.destination_port:
          ports = self._GetPorts()
          if ports:  # Only set when non-empty.
            proto_ports['ports'] = ports
        protocols_and_ports.append(proto_ports)

    if self.api_version == 'ga':
      term_dict['match'] = {layer_4_config: protocols_and_ports}
    else:
      term_dict['match'] = {'config': {layer_4_config: protocols_and_ports}}

    # match needs a field called versionedExpr with value FIREWALL
    # See documentation:
    # https://cloud.google.com/compute/docs/reference/rest/beta/organizationSecurityPolicies/addRule
    term_dict['match']['versionedExpr'] = 'FIREWALL'

    ip_version = self.AF_MAP[self.address_family]
    if ip_version == 4:
      any_ip = [nacaddr.IP('0.0.0.0/0')]
    else:
      any_ip = [nacaddr.IPv6('::/0')]

    if self.term.direction == 'EGRESS':
      daddrs = self.term.GetAddressOfVersion('destination_address', ip_version)
      daddrs = gcp.FilterIPv4InIPv6FormatAddrs(daddrs)

      # If the address got filtered out and is empty due to address family, we
      # don't render the term. At this point of term processing, the direction
      # has already been validated, so we can just log and return empty rule.
      if self.term.destination_address and not daddrs:
        logging.warning(
            'WARNING: Term %s is not being rendered for %s, '
            'because there are no addresses of that family.', self.term.name,
            self.address_family)
        return []
      # This should only happen if there were no addresses set originally.
      if not daddrs:
        daddrs = any_ip

      destination_address_chunks = [
          daddrs[x:x + self._TERM_ADDRESS_LIMIT]
          for x in range(0, len(daddrs), self._TERM_ADDRESS_LIMIT)
      ]

      for daddr_chunk in destination_address_chunks:
        rule = copy.deepcopy(term_dict)
        if self.api_version == 'ga':
          rule['match'][dest_ip_range] = [
              daddr.with_prefixlen for daddr in daddr_chunk
          ]
        else:
          rule['match']['config'][dest_ip_range] = [
              daddr.with_prefixlen for daddr in daddr_chunk
          ]
        rule['priority'] = priority_index
        rules.append(rule)
        priority_index += 1
    else:
      saddrs = gcp.FilterIPv4InIPv6FormatAddrs(
          self.term.GetAddressOfVersion('source_address', ip_version))

      # If the address got filtered out and is empty due to address family, we
      # don't render the term. At this point of term processing, the direction
      # has already been validated, so we can just log and return empty rule.
      if self.term.source_address and not saddrs:
        logging.warning(
            'WARNING: Term %s is not being rendered for %s, '
            'because there are no addresses of that family.', self.term.name,
            self.address_family)
        return []
      # This should only happen if there were no addresses set originally.
      if not saddrs:
        saddrs = any_ip

      source_address_chunks = [
          saddrs[x:x + self._TERM_ADDRESS_LIMIT]
          for x in range(0, len(saddrs), self._TERM_ADDRESS_LIMIT)
      ]
      for saddr_chunk in source_address_chunks:
        rule = copy.deepcopy(term_dict)
        if self.api_version == 'ga':
          rule['match'][src_ip_range] = [
              saddr.with_prefixlen for saddr in saddr_chunk
          ]
        else:
          rule['match']['config'][src_ip_range] = [
              saddr.with_prefixlen for saddr in saddr_chunk
          ]
        rule['priority'] = priority_index
        rules.append(rule)
        priority_index += 1

    return rules

  def __str__(self):
    return ''


class HierarchicalFirewall(gcp.GCP):
  """A GCP Hierarchical Firewall policy."""

  SUFFIX = '.gcphf'
  _ANY_IP = {
      'inet': nacaddr.IP('0.0.0.0/0'),
      'inet6': nacaddr.IP('::/0'),
  }
  _PLATFORM = 'gcp_hf'
  _SUPPORTED_AF = frozenset(['inet', 'inet6', 'mixed'])
  # Beta is the default API version. GA supports IPv6 (inet6/mixed).
  _SUPPORTED_API_VERSION = frozenset(['beta', 'ga'])
  _DEFAULT_MAXIMUM_COST = 100

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      Tuple containing both supported tokens and sub tokens.
    """
    supported_tokens, _ = super()._BuildTokens()

    supported_tokens |= {
        'destination_tag', 'expiration', 'source_tag', 'translated',
        'target_resources', 'logging'
    }

    supported_tokens -= {
        'destination_address_exclude', 'expiration', 'icmp_type',
        'source_address_exclude', 'verbatim'
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
    policies_max_cost = self._DEFAULT_MAXIMUM_COST
    previous_max_cost = -1
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

      # Get the compute API version if set.
      api_version = 'beta'
      for i in self._SUPPORTED_API_VERSION:
        if i in filter_options:
          api_version = i
          filter_options.remove(i)
          break

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

      if previous_max_cost != -1 and previous_max_cost != max_cost:
        raise gcp.HeaderError(
            'Maximum costs of each policy specified must be equal. '
            'Unequal costs found: %d and %d' % (previous_max_cost, max_cost))

      policies_max_cost = max_cost
      previous_max_cost = max_cost

      display_name = ApiVersionSyntaxMap.SYNTAX_MAP[api_version]['display_name']

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
      if display_name in policy and policy[display_name] != policy_name:
        raise DifferentPolicyNameError(
            'Policy names that are from the same policy are expected to be '
            'equal, but %s is different to %s' %
            (policy[display_name], policy_name))
      policy[display_name] = policy_name

      # If there are remaining options, they are unknown/unsupported options.
      if filter_options:
        raise gcp.HeaderError(
            'Unsupported or unknown filter options %s in policy %s ' %
            (str(filter_options), policy_name))

      # Handle mixed for each indvidual term as inet and inet6.
      # inet/inet6 are treated the same.
      term_address_families = []
      if address_family == 'mixed':
        term_address_families = ['inet', 'inet6']
      else:
        term_address_families = [address_family]

      for term in terms:
        if term.stateless_reply:
          continue

        if gcp.IsDefaultDeny(term):
          if direction == 'EGRESS':
            if address_family != 'mixed':
              # Default deny also gets processed as part of terms processing.
              # The name and priority get updated there.
              term.destination_address = [self._ANY_IP[address_family]]
            else:
              term.destination_address = [
                  self._ANY_IP['inet'], self._ANY_IP['inet6']
              ]
          else:
            if address_family != 'mixed':
              term.source_address = [self._ANY_IP[address_family]]
            else:
              term.source_address = [
                  self._ANY_IP['inet'], self._ANY_IP['inet6']
              ]
        term.name = self.FixTermLength(term.name)
        term.direction = direction

        # Only generate the term if it's for the appropriate platform
        if term.platform:
          if self._PLATFORM not in term.platform:
            continue
        if term.platform_exclude:
          if self._PLATFORM in term.platform_exclude:
            continue

        for term_af in term_address_families:
          rules = Term(
              term,
              address_family=term_af,
              policy_inet_version=address_family,
              api_version=api_version).ConvertToDict(priority_index=counter)
          if not rules:
            continue
          for dict_term in rules:
            total_cost += GetRuleTupleCount(dict_term, api_version)
            policy['rules'].append(dict_term)
          counter += len(rules)

    # We want to check the total policy cost, not just per policy.
    if total_cost > policies_max_cost:
      raise ExceededCostError(
          'Policy cost (%d) for %s reached the '
          'maximum (%d)' %
          (total_cost, policy[display_name], policies_max_cost))

    self.policies.append(policy)

    # Do not render an empty rules if no policies have been evaluated.
    if not is_policy_modified:
      self.policies = []

    if total_cost > 0:
      logging.info('Policy %s quota cost: %d',
                   policy[display_name], total_cost)


def GetRuleTupleCount(dict_term: Dict[str, Any], api_version):
  """Calculate the tuple count of a rule in its dictionary form.

  Quota is charged based on how complex the rules are rather than simply
  limiting the number of rules.

  The cost of a rule is the number of distinct protocol:port combinations plus
  the number of IP addresses plus the number of targets.

  Note: The goal of this function is not to determine if a rule is valid, but
      to calculate its tuple count regardless of correctness.

  Args:
    dict_term: A dict object.
    api_version: A string indicating the api version.

  Returns:
    int: The tuple count of the rule.
  """
  layer4_count = 0
  layer_4_config = ApiVersionSyntaxMap.SYNTAX_MAP[api_version]['layer_4_config']
  dest_ip_range = ApiVersionSyntaxMap.SYNTAX_MAP[api_version]['dest_ip_range']
  src_ip_range = ApiVersionSyntaxMap.SYNTAX_MAP[api_version]['src_ip_range']
  targets_count = len(dict_term.get('targetResources', []))
  if api_version == 'ga':
    config = dict_term.get('match', {})
  else:
    config = dict_term.get('match', {}).get('config', {})

  addresses_count = len(
      config.get(dest_ip_range, []) + config.get(src_ip_range, []))

  for l4config in config.get(layer_4_config, []):
    for _ in l4config.get('ports', []):
      layer4_count += 1
    if l4config.get('ipProtocol'):
      layer4_count += +1

  return addresses_count + layer4_count + targets_count
