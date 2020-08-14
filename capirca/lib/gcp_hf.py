"""Google Cloud Hierarchical Firewall Generator.

Hierarchical Firewalls (HF) are represented in a SecurityPolicy GCP resouce.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capirca.lib import gcp
from capirca.lib import nacaddr


class ExceededCostError(gcp.Error):
  """Raised when the total cost of a policy is above the maximum."""


class Term(gcp.Term):
  """Used to create an individual term."""

  ACTION_MAP = {
      'accept': 'allow',
      'next': 'goto_next'
  }

  _MAX_TERM_COMMENT_LENGTH = 64

  _ALLOW_PROTO_NAME = ['tcp', 'udp', 'icmp', 'esp', 'ah', 'sctp']

  def __init__(self, term, address_family='inet'):
    super(Term, self).__init__(term)
    self.address_family = address_family
    self.term = term
    self._ValidateTerm()

  def _ValidateTerm(self):
    if self.term.destination_tag or self.term.source_tag:
      raise gcp.TermError('Hierarchical Firewall does not support tags')

    if self.term.protocol:
      for protocol in self.term.protocol:
        if protocol not in self._ALLOW_PROTO_NAME:
          raise gcp.TermError('Protocol %s is not supported' % protocol)

    if self.term.direction == 'INGRESS':
      if not self.term.source_address:
        raise gcp.TermError('Ingress rule missing source address')
    elif self.term.direction == 'EGRESS':
      if not self.term.destination_address:
        raise gcp.TermError('Egress rule missing destination address')

    for proj, vpc in self.term.target_resources:
      if not gcp.IsProjectIDValid(proj):
        raise gcp.TermError('Project ID "%s" must have lowercase letters, '
                            'digits, or hyphens. It must start with a '
                            'lowercase letter and end with a letter or number.')
      if not gcp.IsVPCNameValid(vpc):
        raise gcp.TermError('VPC name "%s" must start with a lowercase letter '
                            'followed by up to 62 lowercase letters, numbers, '
                            'or hyphens, and cannot end with a hyphen.')
    if self.term.source_port:
      raise gcp.TermError('Hierarchical firewall does not support source port '
                          'restrictions.')

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

    term_dict['description'] = self._TruncateComment(
        self._MAX_TERM_COMMENT_LENGTH)

    ip_version = self.AF_MAP[self.address_family]
    if self.term.direction == 'EGRESS':
      daddrs = self.term.GetAddressOfVersion('destination_address', ip_version)
      term_dict['match'] = {
          'config': {
              'destIpRange': [daddr.with_prefixlen for daddr in daddrs]
          }
      }
    else:
      saddrs = self.term.GetAddressOfVersion('source_address', ip_version)
      term_dict['match'] = {
          'config': {
              'srcIpRange': [saddr.with_prefixlen for saddr in saddrs]
          }
      }
    protocols_and_ports = []
    for proto in self.term.protocol:
      proto_ports = {
          'ipProtocol': proto
      }
      if self.term.destination_port:
        ports = self._GetPorts()
        if ports:  # Only set when non-empty.
          proto_ports['ports'] = ports
      protocols_and_ports.append(proto_ports)

    if protocols_and_ports:  # Only set when non-empty.
      term_dict['match']['config']['layer4Config'] = protocols_and_ports

    return term_dict

  def __str__(self):
    return ''


class HierarchicalFirewall(gcp.GCP):
  """A GCP Hierarchical Firewall policy."""

  SUFFIX = '.gchf'
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

    supported_tokens |= {'destination_tag',
                         'expiration',
                         'source_tag',
                         'translated',
                         'target_resources',
                         'logging'}

    supported_tokens -= {'destination_address_exclude',
                         'expiration',
                         'icmp_type',
                         'option',
                         'platform',
                         'platform_exclude',
                         'source_address_exclude',
                         'verbatim'}

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
    """
    self.policies = []
    for header, terms in pol.filters:
      counter = 1
      total_cost = 0

      policy = {
          'rules': []
      }

      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      # Get the policy name.
      filter_name = header.FilterName(self._PLATFORM)
      filter_options.remove(filter_name)
      policy['display_name'] = filter_name

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

      # If there are remaining options, they are unknown/unsupported options.
      if filter_options:
        raise gcp.HeaderError(
            'Unsupported or unknown filter options %s in policy %s ' %
            (str(filter_options), filter_name))

      for term in terms:
        if term.stateless_reply:
          continue
        total_cost += GetCost(term)
        if total_cost > max_cost:
          raise ExceededCostError('Policy cost (%d) reached the maximum (%d)'
                                  % (total_cost, max_cost))
        if gcp.IsDefaultDeny(term):
          if direction == 'EGRESS':
            term.destination_address = self._ANY
          else:
            term.source_address = self._ANY
        term.name = self.FixTermLength(term.name)
        term.direction = direction
        dict_term = Term(term, address_family=address_family).ConvertToDict(
            priority_index=counter)
        counter += 1
        policy['rules'].append(dict_term)

      self.policies.append(policy)


def GetCost(term):
  """Calculate the cost of a term.

  Quota is charged based on how complex the rules are rather than simply
  limiting the number of rules.

  A firewall rule tuple is the unique combination of IP range, protocol, and
  port defined as a matching condition in a firewall rule. And the cost of a
  firewall rule tuple is the total number of elements within it.

  Args:
    term: A Term object.

  Returns:
    int: The cost of the term.
  """
  protocols = len(term.protocol) or 1
  ports = len(term.destination_port) or 1

  if term.destination_address:
    addresses = len(term.destination_address) or 1
  else:
    addresses = len(term.source_address) or 1

  return addresses * protocols * ports
