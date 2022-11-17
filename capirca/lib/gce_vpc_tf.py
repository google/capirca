# Copyright 2022 Google Inc. All Rights Reserved.
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
"""Terraform GCE config generator.

More information about Terraform and its config syntax:
https://developer.hashicorp.com/terraform/language/syntax/json
"""

import copy
import datetime
import ipaddress
import json
import logging
import re

from typing import Dict, Any

from capirca.lib import gcp
from capirca.lib import nacaddr
import six


class Error(Exception):
  """Generic error class."""


class TerraformFirewallError(Error):
  """Raised with problems in formatting for GCE firewall."""


class ExceededAttributeCountError(Error):
  """Raised when the total attribute count of a policy is above the maximum."""


def IsDefaultDeny(term):
  """Returns true if a term is a default deny without IPs, ports, etc."""
  skip_attrs = [
      'flattened', 'flattened_addr', 'flattened_saddr', 'flattened_daddr',
      'action', 'comment', 'name', 'logging'
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


class Term(gcp.Term):
  """Creates the term for the Terraform GCE config."""

  ACTION_MAP = {'accept': 'allow', 'deny': 'deny'}
  # Restrict the number of addresses per term to 256.
  # Similar restrictions apply to source and target tags, and ports.
  # Details: https://cloud.google.com/vpc/docs/quota#per_network_2
  _TERM_ADDRESS_LIMIT = 256
  _TERM_SOURCE_TAGS_LIMIT = 30
  _TERM_TARGET_TAGS_LIMIT = 70
  _TERM_SERVICE_ACCOUNTS_LIMIT = 10
  _TERM_PORTS_LIMIT = 256

  # Firewall rule name has to match specific RE:
  # The first character must be a lowercase letter, and all following characters
  # must be a dash, lowercase letter, or digit, except the last character, which
  # cannot be a dash.
  # Details: https://cloud.google.com/compute/docs/reference/latest/firewalls
  _TERM_NAME_RE = re.compile(r'^[a-z]([-a-z0-9]*[a-z0-9])?$')

  # Protocols allowed by name from:
  # https://cloud.google.com/vpc/docs/firewalls#protocols_and_ports
  _ALLOW_PROTO_NAME = frozenset([
      'tcp',
      'udp',
      'icmp',
      'esp',
      'ah',
      'ipip',
      'sctp',
      'all'  # Needed for default deny, do not use in policy file.
  ])

  # Any protocol not in _ALLOW_PROTO_NAME must be passed by number.
  ALWAYS_PROTO_NUM = set(gcp.Term.PROTO_MAP.keys()) - _ALLOW_PROTO_NAME
  #DENY_ALL_PRIORITY = 65534

  def __init__(self, term, inet_version='inet', policy_inet_version='inet'):
    super().__init__(term)
    self.term = term
    self.inet_version = inet_version
    # This is to handle mixed, where the policy_inet_version is mixed,
    # but the term inet version is either inet/inet6.
    # This is only useful for term name and priority.
    self.policy_inet_version = policy_inet_version

    self._validateDirection()
    if self.term.source_address_exclude and not self.term.source_address:
      raise TerraformFirewallError(
          'GCE firewall does not support address exclusions without a source '
          'address list.')
    # The reason for the error below isn't because of a GCE restriction, but
    # because we don't want to use a bad default of GCE that allows talking
    # to anything when there's no source address, source tag, or source service
    # account.
    if (not self.term.source_address and
        not self.term.source_tag) and self.term.direction == 'INGRESS':
      raise TerraformFirewallError(
          'GCE firewall needs either to specify source address or source tags.')
    if self.term.source_port:
      raise TerraformFirewallError(
          'GCE firewall does not support source port restrictions.')
    if (self.term.source_address_exclude and self.term.source_address or
        self.term.destination_address_exclude and
        self.term.destination_address):
      self.term.FlattenAll()
      if not self.term.source_address and self.term.direction == 'INGRESS':
        raise TerraformFirewallError(
            'GCE firewall rule no longer contains any source addresses after '
            'the prefixes in source_address_exclude were removed.')
      # Similarly to the comment above, the reason for this error is also
      # because we do not want to use the bad default of GCE that allows for
      # talking to anything when there is no IP address provided for this field.
      if not self.term.destination_address and self.term.direction == 'EGRESS':
        raise TerraformFirewallError(
            'GCE firewall rule no longer contains any destination addresses '
            'after the prefixes in destination_address_exclude were removed.')

  def __str__(self):
    """Convert term to a string."""
    json.dumps(
        self.ConvertToDict(priority_index=1),
        indent=2,
        separators=(six.ensure_str(','), six.ensure_str(': ')))

  def _validateDirection(self):
    if self.term.direction == 'INGRESS':
      if not self.term.source_address and not self.term.source_tag:
        raise TerraformFirewallError(
            'Ingress rule missing required field oneof "source_ranges" or '
            '"source_tags".')

      if self.term.destination_address:
        raise TerraformFirewallError('Ingress rules cannot include '
                                     '"destination_ranges.')

    elif self.term.direction == 'EGRESS':
      if self.term.source_address:
        raise TerraformFirewallError(
            'Egress rules cannot include "source_ranges".')

      if not self.term.destination_address:
        raise TerraformFirewallError(
            'Egress rule missing required field "destination_ranges".')

      if self.term.destination_tag:
        raise TerraformFirewallError(
            'GCE Egress rule cannot have destination tag.')

  def ConvertToDict(self, priority_index):
    """Convert term to a dictionary.

    This is used to get a dictionary describing this term which can be
    output easily as a JSON blob.

    Args:
      priority_index: An integer priority value assigned to the term.

    Returns:
      A dictionary that contains all fields necessary to create or update a GCE
      firewall.

    Raises:
      TerraformFirewallError: The term name is too long.
    """
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    term_dict = {
        'description': ' '.join(self.term.comment),
        'name': self.term.name,
        'direction': self.term.direction,
        'priority': priority_index
    }
    if self.term.network:
      term_dict['network'] = self.term.network
      term_dict['name'] = '%s-%s' % (self.term.network.split('/')[-1],
                                     term_dict['name'])
    # Identify if this is inet6 processing for a term under a mixed policy.
    mixed_policy_inet6_term = False
    if self.policy_inet_version == 'mixed' and self.inet_version == 'inet6':
      mixed_policy_inet6_term = True
    # Update term name to have the IPv6 suffix for the inet6 rule.
    if mixed_policy_inet6_term:
      term_dict['name'] = gcp.GetIpv6TermName(term_dict['name'])

    # Checking counts of tags, and ports to see if they exceeded limits.
    if len(self.term.source_tag) > self._TERM_SOURCE_TAGS_LIMIT:
      raise TerraformFirewallError(
          'GCE firewall rule exceeded number of source tags per rule: %s' %
          self.term.name)
    if len(self.term.destination_tag) > self._TERM_TARGET_TAGS_LIMIT:
      raise TerraformFirewallError(
          'GCE firewall rule exceeded number of target tags per rule: %s' %
          self.term.name)
    if len(
        self.term.source_service_accounts
    ) > self._TERM_SERVICE_ACCOUNTS_LIMIT or len(
        self.term.target_service_accounts) > self._TERM_SERVICE_ACCOUNTS_LIMIT:
      raise TerraformFirewallError(
          'GCE firewall rule exceeded number of service accounts per rule: %s' %
          self.term.name)

    if self.term.source_tag:
      if self.term.direction == 'INGRESS':
        term_dict['source_tags'] = self.term.source_tag
      elif self.term.direction == 'EGRESS':
        term_dict['target_tags'] = self.term.source_tag
    if self.term.destination_tag and self.term.direction == 'INGRESS':
      term_dict['target_tags'] = self.term.destination_tag
    if self.term.source_service_accounts:
      if 'target_tags' in term_dict or 'source_tags' in term_dict:
        raise TerraformFirewallError(
            'source_service_accounts cannot be used at the same time as target_tags or source_tags: %s'
            % self.term.source_service_accounts)
      term_dict['source_service_accounts'] = self.term.source_service_accounts
    if self.term.target_service_accounts:
      if 'target_tags' in term_dict or 'source_tags' in term_dict:
        raise TerraformFirewallError(
            'target_service_accounts cannot be used at the same time as target_tags or source_tags: %s'
            % self.term.target_service_accounts)
      term_dict['target_service_accounts'] = self.term.target_service_accounts
    # If priority is explicitly set, it'll be used.  Otherwise the sequence will
    # be incremented.
    if self.term.priority:
      term_dict['priority'] = self.term.priority

    rules = []
    # If 'mixed' ends up in indvidual term inet_version, something has gone
    # horribly wrong. The only valid values are inet/inet6.
    term_af = self.AF_MAP.get(self.inet_version)
    if self.inet_version == 'mixed':
      raise TerraformFirewallError(
          'GCE firewall rule has incorrect inet_version for rule: %s' %
          self.term.name)

    # Exit early for inet6 processing of mixed rules that have only tags,
    # and no IP addresses, since this is handled in the inet processing.
    if mixed_policy_inet6_term:
      if not self.term.source_address and not self.term.destination_address:
        if 'target_tags' in term_dict or 'source_tags' in term_dict:
          return []

    saddrs = sorted(
        self.term.GetAddressOfVersion('source_address', term_af),
        key=ipaddress.get_mixed_type_key)
    saddrs = gcp.FilterIPv4InIPv6FormatAddrs(saddrs)
    daddrs = sorted(
        self.term.GetAddressOfVersion('destination_address', term_af),
        key=ipaddress.get_mixed_type_key)
    daddrs = gcp.FilterIPv4InIPv6FormatAddrs(daddrs)

    # If the address got filtered out and is empty due to address family, we
    # don't render the term. At this point of term processing, the direction
    # has already been validated, so we can just log and return empty rule.
    if self.term.source_address and not saddrs:
      logging.warning(
          'WARNING: Term %s is not being rendered for %s, '
          'because there are no addresses of that family.', self.term.name,
          self.inet_version)
      return []
    if self.term.destination_address and not daddrs:
      logging.warning(
          'WARNING: Term %s is not being rendered for %s, '
          'because there are no addresses of that family.', self.term.name,
          self.inet_version)
      return []

    filtered_protocols = []
    if not self.term.protocol:
      # Any protocol is represented as "all"
      filtered_protocols = ['all']
      logging.info(
          'INFO: Term %s has no protocol specified,'
          'which is interpreted as "all" protocols.', self.term.name)

    proto_dict = copy.deepcopy(term_dict)

    if self.term.logging:
      proto_dict['log_config'] = {'metadata': 'INCLUDE_ALL_METADATA'}

    for proto in self.term.protocol:
      # ICMP filtering by inet_version
      # Since each term has inet_version, 'mixed' is correctly processed here.
      # Convert protocol to number for uniformity of comparison.
      # PROTO_MAP always returns protocol number.
      if proto in self._ALLOW_PROTO_NAME:
        proto_num = self.PROTO_MAP[proto]
      else:
        proto_num = proto
      if proto_num == self.PROTO_MAP['icmp'] and self.inet_version == 'inet6':
        logging.warning(
            'WARNING: Term %s is being rendered for inet6, ICMP '
            'protocol will not be rendered.', self.term.name)
        continue
      if proto_num == self.PROTO_MAP['icmpv6'] and self.inet_version == 'inet':
        logging.warning(
            'WARNING: Term %s is being rendered for inet, ICMPv6 '
            'protocol will not be rendered.', self.term.name)
        continue
      if proto_num == self.PROTO_MAP['igmp'] and self.inet_version == 'inet6':
        logging.warning(
            'WARNING: Term %s is being rendered for inet6, IGMP '
            'protocol will not be rendered.', self.term.name)
        continue
      filtered_protocols.append(proto)
    # If there is no protocol left after ICMP/IGMP filtering, drop this term.
    if not filtered_protocols:
      return []
    for proto in filtered_protocols:
      # If the protocol name is not supported, protocol number is used.
      # This is done by default in policy.py.
      if proto not in self._ALLOW_PROTO_NAME:
        logging.info('INFO: Term %s is being rendered using protocol number',
                     self.term.name)
      dest = {'protocol': proto}

      if self.term.destination_port:
        ports = []
        for start, end in self.term.destination_port:
          if start == end:
            ports.append(str(start))
          else:
            ports.append('%d-%d' % (start, end))
        if len(ports) > self._TERM_PORTS_LIMIT:
          raise TerraformFirewallError(
              'GCE firewall rule exceeded number of ports per rule: %s' %
              self.term.name)
        dest['ports'] = ports

      action = self.ACTION_MAP[self.term.action[0]]
      dict_val = []
      if action in proto_dict:
        dict_val = proto_dict[action]
        if not isinstance(dict_val, list):
          dict_val = [dict_val]
      dict_val.append(dest)
      proto_dict[action] = dict_val

    # There's a limit of 256 addresses each term can contain.
    # If we're above that limit, we're breaking it down in more terms.
    if saddrs:
      source_addr_chunks = [
          saddrs[x:x + self._TERM_ADDRESS_LIMIT]
          for x in range(0, len(saddrs), self._TERM_ADDRESS_LIMIT)
      ]
      for i, chunk in enumerate(source_addr_chunks):
        rule = copy.deepcopy(proto_dict)
        if len(source_addr_chunks) > 1:
          rule['name'] = '%s-%d' % (rule['name'], i + 1)
        rule['source_ranges'] = [str(saddr) for saddr in chunk]
        # if rule[
        #     'priority'] != Term.DENY_ALL_PRIORITY:  # If not the deny-all rule.
        rule['priority'] = priority_index
        priority_index += 1
        rules.append(rule)
    elif daddrs:
      dest_addr_chunks = [
          daddrs[x:x + self._TERM_ADDRESS_LIMIT]
          for x in range(0, len(daddrs), self._TERM_ADDRESS_LIMIT)
      ]
      for i, chunk in enumerate(dest_addr_chunks):
        rule = copy.deepcopy(proto_dict)
        if len(dest_addr_chunks) > 1:
          rule['name'] = '%s-%d' % (rule['name'], i + 1)
        rule['destination_ranges'] = [str(daddr) for daddr in chunk]
        # if rule[
        #     'priority'] != Term.DENY_ALL_PRIORITY:  # If not the deny-all rule.
        rule['priority'] = priority_index
        priority_index += 1
        rules.append(rule)
    else:
      rules.append(proto_dict)

    # Sanity checking term name lengths.
    long_rules = [rule['name'] for rule in rules if len(rule['name']) > 63]
    if long_rules:
      raise TerraformFirewallError(
          'GCE firewall name ended up being too long: %s' % long_rules)

    # Attach the name of the rule to the inner array.
    new_rule = {}
    final_rules = []
    for rule in rules:
      rule_name = rule['name']
      new_rule[rule_name] = rule
    final_rules.append(new_rule)
    return final_rules


class TerraformGCE(gcp.GCP):
  """A Terraform GCE config."""

  _PLATFORM = 'gce_vpc_tf'
  SUFFIX = '.tf.json'
  # NOTE: While this code will generate inet6/mixed rules, terraform doesn't
  # currently support this (but hopefully will soon, which is why it is coded).
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
  _ANY_IP = {
      'inet': nacaddr.IP('0.0.0.0/0'),
      'inet6': nacaddr.IP('::/0'),
  }
  # Supported is 63 but we need to account for dynamic updates when the term
  # is rendered (which can add proto and a counter).
  _TERM_MAX_LENGTH = 53
  _GOOD_DIRECTION = ['INGRESS', 'EGRESS']
  _OPTIONAL_SUPPORTED_KEYWORDS = frozenset([
      'expiration', 'destination_tag', 'source_tag', 'source_service_accounts',
      'target_service_accounts'
  ])

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, _ = super()._BuildTokens()

    # add extra things
    supported_tokens |= {
        'destination_tag', 'expiration', 'owner', 'priority', 'source_tag',
        'source_service_accounts', 'target_service_accounts'
    }

    # remove unsupported things
    supported_tokens -= {'icmp_type', 'verbatim'}
    # easier to make a new structure
    supported_sub_tokens = {'action': {'accept', 'deny'}}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    # Add "google_compute_firewall" label to the outer json dict.
    self.terraform_resources = {'google_compute_firewall': []}
    max_attribute_count = 0
    total_attribute_count = 0
    total_rule_count = 0
    priority_counter = 1

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
      # Get the address family if set.
      address_family = 'inet'
      for i in self._SUPPORTED_AF:
        if i in ['inet6', 'mixed']:
          logging.error('Terraform does not currently support ipv6!')
        if i in filter_options:
          address_family = i
          filter_options.remove(i)

      for opt in filter_options:
        try:
          max_attribute_count = int(opt)
          logging.info('Checking policy for max attribute count %d',
                       max_attribute_count)
          filter_options.remove(opt)
          break
        except ValueError:
          continue

      if filter_options:
        network = filter_options[0]
      else:
        raise TerraformFirewallError('GCE filter does not specify a network.')

      term_names = set()
      if IsDefaultDeny(terms[-1]):
        terms[-1].protocol = ['all']
        #terms[-1].priority = Term.DENY_ALL_PRIORITY
        if direction == 'EGRESS':
          if address_family != 'mixed':
            # Default deny also gets processed as part of terms processing.
            # The name and priority get updated there.
            terms[-1].destination_address = [self._ANY_IP[address_family]]
          else:
            terms[-1].destination_address = [
                self._ANY_IP['inet'], self._ANY_IP['inet6']
            ]
        else:
          if address_family != 'mixed':
            terms[-1].source_address = [self._ANY_IP[address_family]]
          else:
            terms[-1].source_address = [
                self._ANY_IP['inet'], self._ANY_IP['inet6']
            ]

      for term in terms:
        if term.stateless_reply:
          logging.warning(
              'WARNING: Term %s in policy %s is a stateless reply '
              'term and will not be rendered.', term.name, filter_name)
          continue
        term.network = network
        if not term.comment:
          term.comment = header.comment
        if direction == 'EGRESS':
          term.name += '-e'
        term.name = self.FixTermLength(term.name)
        if term.name in term_names:
          raise TerraformFirewallError('Duplicate term name %s' % term.name)
        term_names.add(term.name)

        term.direction = direction
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info(
                'INFO: Term %s in policy %s expires '
                'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning(
                'WARNING: Term %s in policy %s is expired and '
                'will not be rendered.', term.name, filter_name)
            continue
        if term.option:
          raise TerraformFirewallError(
              'GCE firewall does not support term options.')

        # Only generate the term if it's for the appropriate platform
        if term.platform:
          if self._PLATFORM not in term.platform:
            continue
        if term.platform_exclude:
          if self._PLATFORM in term.platform_exclude:
            continue

        # Handle mixed for each indvidual term as inet and inet6.
        # inet/inet6 are treated the same.
        term_address_families = []
        if address_family == 'mixed':
          term_address_families = ['inet', 'inet6']
        else:
          term_address_families = [address_family]
        for term_af in term_address_families:
          for rules in Term(
              term, term_af,
              address_family).ConvertToDict(priority_index=priority_counter):
            for rule_key, rule_dict in rules.items():
              logging.debug('Attribute count of rule %s is: %d', rule_key,
                            GetAttributeCount(rule_dict))
              total_attribute_count += GetAttributeCount(rule_dict)
              total_rule_count += 1
            if max_attribute_count and total_attribute_count > max_attribute_count:
              # Stop processing rules as soon as the attribute count is over the
              # limit.
              raise ExceededAttributeCountError(
                  'Attribute count (%d) for %s exceeded the maximum (%d)' %
                  (total_attribute_count, filter_name, max_attribute_count))
            self.terraform_resources['google_compute_firewall'].append(rules)
            priority_counter += len(rules)
    logging.info('Total rule count of policy %s is: %d', filter_name,
                 total_rule_count)
    logging.info('Total attribute count of policy %s is: %d', filter_name,
                 total_attribute_count)
    self.resource_wrapper = {'resource': self.terraform_resources}

  def __str__(self):
    out = '%s\n\n' % (
        json.dumps(
            self.resource_wrapper,
            indent=2,
            separators=(six.ensure_str(','), six.ensure_str(': ')),
            sort_keys=True))
    return out


def GetAttributeCount(dict_term: Dict[str, Any]) -> int:
  """Calculate the attribute count of a term in its dictionary form.

  The attribute count of a rule is the sum of the number of ports, protocols, IP
  ranges, tags and target service account.

  Note: The goal of this function is not to determine if a term is valid, but
      to calculate its attribute count regardless of correctness.

  Args:
    dict_term: A dict object.

  Returns:
    int: The attribute count of the term.
  """
  addresses = (
      len(dict_term.get('destination_ranges', [])) or
      len(dict_term.get('source_ranges', [])))

  proto_ports = 0
  for allowed in dict_term.get('allow', []):
    proto_ports += len(allowed.get('ports', [])) + 1  # 1 for ipProtocol
  for denied in dict_term.get('deny', []):
    proto_ports += len(denied.get('ports', [])) + 1  # 1 for ipProtocol

  tags = 0
  for _ in dict_term.get('source_tags', []):
    tags += 1
  for _ in dict_term.get('target_tags', []):
    tags += 1

  service_accounts = 0
  for _ in dict_term.get('source_service_accounts', []):
    service_accounts += 1
  for _ in dict_term.get('target_service_accounts', []):
    service_accounts += 1
  return addresses + proto_ports + tags + service_accounts
