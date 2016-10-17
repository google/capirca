# Copyright 2014 Google Inc. All Rights Reserved.
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

"""nftables generator.

nftables is the new packet classification framework that intends to replace
the existing {ip,ip6,arp,eb}_tables infrastructure.

nftables syntax is radically different from iptables and therefore this
generator inherits directly from aclgenerator.

"""

__author__ = 'vklimovs@google.com (Vjaceslavs Klimovs)'

import collections
import datetime

from lib import aclgenerator
from lib import nacaddr
import logging


class Error(Exception):
  """Base error class."""


class InvalidTargetOption(Error):
  """Raised when target specification is invalid."""


class Term(aclgenerator.Term):
  """Representation of an individual nftables term.

  This is mostly useful for the __str__() method.

  """

  _PLATFORM = 'nftables'
  _ACTIONS = {'accept': 'accept',
              'deny': 'drop',
              'reject': 'reject',
              'next': 'continue',
              'reject-with-tcp-rst': 'reject with tcp reset'}

  def __init__(self, term, af):
    """Setup a new nftables term.

    Args:
      term: A policy.Term object
      af: The address family for the term, "inet" or "inet6"
    """
    super(Term, self).__init__(term)
    self.term = term
    self.af = af
    if af == 'inet6':
      self.all_ips = nacaddr.IPv6('::/0')
    else:
      self.all_ips = nacaddr.IPv4('0.0.0.0/0')

  # TODO(vklimovs): some not trivial processing is happening inside this
  # __str__, replace with explicit method
  def __str__(self):
    output = []

    # Don't render term if not in platforms or in excluded platforms
    if self.term.platform and self._PLATFORM not in self.term.platform:
      return ''
    if (self.term.platform_exclude and
        self._PLATFORM in self.term.platform_exclude):
      return ''

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 'inet6' and 'icmp' in self.term.protocol) or
        (self.af == 'inet' and 'icmpv6' in self.term.protocol)):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(term=self.term.name,
                                                    proto=self.term.protocol,
                                                    af=self.af))
      return ''

    # Term verbatim output - this will skip over most normal term
    # creation code by returning early. Warnings provided in policy.py.
    if self.term.verbatim:
      for verbatim_line in self.term.verbatim:
        platform, contents = verbatim_line.value
        if platform == self._PLATFORM:
          output.append(str(contents))
      return '\n'.join(output)

    # Source address
    if self.term.source_address or self.term.source_address_exclude:
      src_addrs = self._CalculateAddrs(self.term.source_address,
                                       self.term.source_address_exclude)
      if not src_addrs:
        logging.warn(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                    direction='source',
                                                    af=self.af))
        return ''
      output.append('ip saddr %s' % self._FormatMatch(src_addrs))

    # Destination address
    if self.term.destination_address or self.term.source_address_exclude:
      dst_addrs = self._CalculateAddrs(self.term.destination_address,
                                       self.term.destination_address_exclude)
      if not dst_addrs:
        logging.warn(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                    direction='destination',
                                                    af=self.af))
        return ''
      output.append('ip daddr %s' % self._FormatMatch(dst_addrs))

    # Protocol
    #
    # nft intepreter shortcuts protocol specification if there are more specific
    # matches. At the moment, these are:
    # * source port
    # * destination port
    # * ICMP type
    if self.term.protocol and not (self.term.source_port or
                                   self.term.destination_port or
                                   self.term.icmp_type):
      output.append('ip protocol %s' % self._FormatMatch(self.term.protocol))

    # Source port
    if self.term.source_port:
      output.append('%s sport %s' %
                    (self._FormatMatch(self.term.protocol),
                     self._FormatMatch(self.term.source_port)))

    # Destination port
    if self.term.destination_port:
      output.append('%s dport %s' %
                    (self._FormatMatch(self.term.protocol),
                     self._FormatMatch(self.term.destination_port)))

    # Icmp type
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol,
                                           self.af)
      if icmp_types != ['']:
        # nft intepreter requires ICMP types to be spelled out
        icmp_name_types = self.ICMP_TYPE[self.AF_MAP[self.af]]
        icmp_type_names = dict((v, k) for k, v in icmp_name_types.iteritems())
        output.append('icmp type %s' %
                      self._FormatMatch([icmp_type_names[icmp_type] for
                                         icmp_type in icmp_types]))

    # Action
    output.append(self._ACTIONS[self.term.action[0]])

    # Owner
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)

    # Comment
    if self.term.comment:
      output.append('comment "%s"' % ' '.join(self.term.comment))

    return ' '.join(output)

  def _CalculateAddrs(self, addr_list, addr_exclude_list):
    addr_list = [addr for addr in addr_list
                 if addr.version == self.AF_MAP[self.af]]
    if addr_exclude_list:
      if not addr_list:
        addr_list = [self.all_ips]
      addr_list = nacaddr.ExcludeAddrs(addr_list, addr_exclude_list)
    return addr_list

  def _FormatMatch(self, match):
    output = []
    for element in match:
      # Special case: port range
      if isinstance(element, tuple):
        range_start, range_end = element
        if range_start == range_end:
          output.append('%d' % range_start)
        else:
          output.append('%d-%d' % (range_start, range_end))
      else:
        output.append(str(element))
    if len(output) > 1:
      # idiosyncrasy of nftables output: no leading space to trailing }
      return '{ ' + ', '.join(output) + '}'
    else:
      return output[0]


class Nftables(aclgenerator.ACLGenerator):
  """nftables generator.

    This class takes a policy object and renders the output into a syntax
    which is nft intepreter.
  """

  SUFFIX = '.nft'
  _PLATFORM = 'nftables'
  _TERM = Term
  _VALID_ADDRESS_FAMILIES = {'inet': 'ip', 'inet6': 'ip6'}
  _VALID_HOOK_NAMES = set(['prerouting', 'input', 'forward',
                           'output', 'postrouting'])

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(
        Nftables, self)._BuildTokens()

    supported_tokens |= {'owner'}
    del supported_sub_tokens['option']
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, policy, expiration):
    """Translates policy contents to platform specific data structures.

    Args:
      policy: policy object to be transalted to platform specific data
        structures.
      expiration: integer number of weeks to be warned about term expiration in.

    Raises:
      InvalidTargetOption: if supplied target options are invalid.

    """
    self.tables = collections.defaultdict(list)

    for header, terms in policy.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if not filter_options:
        raise InvalidTargetOption('Chain name not specified.')

      if len(filter_options) > 4:
        raise InvalidTargetOption('Too many target options.')

      # Address family, optional
      af = 'inet'
      if len(filter_options) == 4:
        af = filter_options[3]
        if af not in self._VALID_ADDRESS_FAMILIES:
          raise InvalidTargetOption(
              'Specified address family (%s) is not supported.' % af)

      # Hook name and chain priority, optional but both or none
      chain_priority = None
      hook_name = None
      if len(filter_options) >= 3:
        try:
          chain_priority = str(int(filter_options[2]))
        except ValueError:
          raise InvalidTargetOption(
              'Specified priority is not an integer (%s).' % filter_options[2])
        hook_name = filter_options[1]
        if hook_name not in self._VALID_HOOK_NAMES:
          raise InvalidTargetOption(
              'Specified hook name (%s) is not a valid hook name.' % hook_name)

      if len(filter_options) == 2:
        raise InvalidTargetOption(
            'Either hook name or chain priority is not specified.')

      # Chain name, mandatory
      chain_name = filter_options[0]

      if not hook_name or not chain_priority:
        logging.info('Chain %s is a non-base chain, make sure it is linked.',
                     chain_name)

      # Terms
      valid_terms = []
      for term in terms:
        term = self.FixHighPorts(term, af)
        if not term:
          continue

        current_date = datetime.datetime.utcnow().date()
        expiration_date = current_date + datetime.timedelta(weeks=expiration)

        if term.expiration:
          if term.expiration < current_date:
            logging.warn(
                'Term %s in policy %s is expired and will not be rendered.',
                term.name, chain_name)
            continue
          if term.expiration <= expiration_date:
            logging.info('Term %s in policy %s expires in less than %d weeks.',
                         term.name, chain_name, expiration)

        valid_terms.append(self._TERM(term, af))

      # Add to appropriate table
      self.tables[af].append((chain_name, hook_name,
                              chain_priority, valid_terms))

  # TODO(vklimovs): some not trivial processing is happening inside this
  # __str__, replace with explicit method
  def __str__(self):
    output = []

    # Iterate over tables
    for af in sorted(self.tables):
      output.append('flush table %s filter' %
                    self._VALID_ADDRESS_FAMILIES[af])
      output.append('table %s filter {' %
                    self._VALID_ADDRESS_FAMILIES[af])

      # Iterate over chains
      for (chain_name, hook_name,
           chain_priority, valid_terms) in self.tables[af]:
        output.append('\tchain %s {' % chain_name)
        if hook_name and chain_priority:
          output.append('\t\ttype filter hook %s priority %s;' %
                        (hook_name, chain_priority))
          for valid_term in valid_terms:
            term_string = str(valid_term)
            if term_string:
              output.append('\t\t' + term_string)
        output.append('\t}')  # chain
      output.append('}')  # table
    return '\n'.join(output)
