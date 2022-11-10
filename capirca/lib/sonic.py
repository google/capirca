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
"""SONiC CONFIG_DB ACL generator."""

import copy
import datetime
import json
import logging

from capirca.lib import aclgenerator


class Error(Exception):
  """Generic error class."""


class Term(aclgenerator.Term):
  """Creates the term for the SONiC CONFIG_DB ACL."""

  # Capirca to SONiC config_db policy action map.
  ACTION_MAP = {'accept': 'FORWARD', 'deny': 'DROP'}

  def __init__(self, term, inet_version='inet', platform='sonic'):
    super().__init__(term)
    self.term = term
    self.inet_version = inet_version
    self.af = self.AF_MAP.get(self.inet_version)
    self.platform = platform
    # Combine (flatten) addresses with their exclusions into a resulting
    # flattened_saddr, flattened_daddr, flattened_addr.
    self.term.FlattenAll()

  def ConvertToDict(self):
    if not self.term.action:
      logging.info('Skipping term with empty action %s', self.term)
      return []

    if self.term.platform:
      if self.platform not in self.term.platform:
        return []

    a = self.term.action[0]
    action = self.ACTION_MAP[a]

    if self.term.protocol == ['icmp'] and self.af == 6:
      # proto and ip version mismatch
      return []
    if self.term.protocol == ['icmpv6'] and self.af == 4:
      # proto and ip version mismatch
      return []

    protos = self.term.protocol
    if not protos:
      protos = [None]

    tcp_flags = []
    if self.term.option:
      for opt in [str(x) for x in self.term.option]:
        if opt == 'tcp-established':
          tcp_flags = [
              '0x10/0x10',  # ACK
              '0x4/0x4',  # RST
          ]

    icmp_types = []
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.af)
    if not icmp_types:
      icmp_types = [None]

    sports = self.term.source_port
    if not sports:
      sports = [(0, 0)]
    dports = self.term.destination_port
    if not dports:
      dports = [(0, 0)]

    src_ip_key = 'SRC_IP'
    dst_ip_key = 'DST_IP'
    icmp_type_key = 'ICMP_TYPE'
    if self.af == 6:
      src_ip_key = 'SRC_IPV6'
      dst_ip_key = 'DST_IPV6'
      icmp_type_key = 'ICMPV6_TYPE'

    if not self._HasBothAddressFamiliesIPs('flattened_saddr'):
      return []
    saddrs = self.term.GetAddressOfVersion('flattened_saddr', self.af)
    if not saddrs:
      saddrs = [None]

    if not self._HasBothAddressFamiliesIPs('flattened_daddr'):
      return []
    daddrs = self.term.GetAddressOfVersion('flattened_daddr', self.af)
    if not daddrs:
      daddrs = [None]
    rules = []
    rule_dict = {
        'PACKET_ACTION': action,
    }
    for proto in protos:
      if proto is not None:
        # TODO: do we need to handle a case when the proto is a number?
        rule_dict['IP_PROTOCOL'] = str(self.PROTO_MAP[proto])
      if proto == 'tcp' and tcp_flags:
        rule_dict['TCP_FLAGS'] = tcp_flags
      for icmp_type in icmp_types:
        if icmp_type is not None:
          rule_dict[icmp_type_key] = str(icmp_type)
        for saddr in saddrs:
          if saddr:
            rule_dict[src_ip_key] = str(saddr)
          for daddr in daddrs:
            if daddr:
              rule_dict[dst_ip_key] = str(daddr)
            for start, end in sports:
              if not start == end == 0:
                if start == end:
                  rule_dict['L4_SRC_PORT'] = str(start)
                else:
                  rule_dict['L4_SRC_PORT_RANGE'] = f'{start}-{end}'
              for start, end in dports:
                if not start == end == 0:
                  if start == end:
                    rule_dict['L4_DST_PORT'] = str(start)
                  else:
                    rule_dict['L4_DST_PORT_RANGE'] = f'{start}-{end}'
                rules.append(copy.deepcopy(rule_dict))
    return rules

  def _HasBothAddressFamiliesIPs(self, address_type):
    """Checks if requested src/dst IPs of of matching term af exist.

    Args:
      address_type: Could be either flattened_saddr or flattened_daddr. Str.

    Returns:
      True if address_type of matching term af exists or False otherwise.

    Raises:
      Error: if unsupported address_type is passed.
    """
    if address_type not in ['flattened_saddr', 'flattened_daddr']:
      raise Error(f'_HasBothAddressFamiliesIPs does not support {address_type}')
    addrs_af4 = self.term.GetAddressOfVersion(address_type, 4)
    addrs_af6 = self.term.GetAddressOfVersion(address_type, 6)
    if self.af == 4:
      if not addrs_af4 and addrs_af6:
        # We have IPv6 addresses, but no IPv4 - don't render this term for IPv4.
        return False
    else:
      if not addrs_af6 and addrs_af4:
        # We have IPv4 addresses, but no IPv6 - don't render this term for IPv6.
        return False
    return True

  def __str__(self):
    """Convert term to a string."""
    rules = self.ConvertToDict()
    return json.dumps(rules, indent=2)


class Sonic(aclgenerator.ACLGenerator):
  """A SONiC config_db ACL policy object."""
  _PLATFORM = 'sonic'
  SUFFIX = '.sonicacl'
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
  _rule_counter = 0
  _rule_increment = 10
  _rule_priority = 65536

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    # Remove unsupported things.
    unsupported_tokens = {
        'verbatim', 'stateless_reply', 'platform_exclude', 'platform',
        'source_address_exclude', 'destination_address_exclude'
    }
    supported_tokens -= unsupported_tokens

    # SONiC ACL model only supports these three forwarding actions.
    supported_sub_tokens['action'] = {'accept', 'deny'}
    # Simplify SONiC ACL model down to these options.
    supported_sub_tokens['option'] = {'tcp-established'}

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.sonic_policy = {}

    current_date = datetime.datetime.now(datetime.timezone.utc).date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      # Options are anything after the platform name in the target message of
      # the policy header, [1:].
      filter_options = header.FilterOptions(self._PLATFORM)

      # TODO: assume first item as a policy name.
      if filter_options:
        filter_name = filter_options[0]
      else:
        raise Error('Unable to find policy name')

      term_address_families = set()
      for i in self._SUPPORTED_AF:
        if i in filter_options:
          if i == 'mixed':
            term_address_families.update(
                self._SUPPORTED_AF.difference(['mixed']))
          else:
            term_address_families.add(i)
      if not term_address_families:
        # No supported families.
        logging.info('Skipping policy %s as it does not apply to any of %s',
                     filter_name, self._SUPPORTED_AF)
        continue

      for term in terms:
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
        for term_af in term_address_families:
          t = Term(term=term, inet_version=term_af)
          for rule in t.ConvertToDict():
            if not rule:
              continue
            self._rule_counter += self._rule_increment
            self._rule_priority -= self._rule_increment
            if self._rule_priority < 0:
              raise Error('Rule priority can not be less than zero')
            rule_name = f'{filter_name}|RULE_{self._rule_counter}'
            rule['PRIORITY'] = str(self._rule_priority)
            self.sonic_policy[rule_name] = rule

      self.sonic_policy = {'ACL_RULE': self.sonic_policy}

  # This is what actually "renders" the policy into vendor-specific
  # representation!
  def __str__(self):
    return json.dumps(self.sonic_policy, indent=2, separators=(',', ': '))
