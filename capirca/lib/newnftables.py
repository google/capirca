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
"""NFtables policy generator for capirca."""

import collections
import datetime
import logging

from capirca.lib import aclgenerator
from capirca.lib import nacaddr


class Error(Exception):
  """Base error class."""


class TermError(Error):
  """Raised when a term is not valid."""


class HeaderError(Error):
  """Raised when a header is not valid."""


class UnsupportedFilterTypeError(Error):
  """Raised when an unsupported filter type is specified."""


class Term(aclgenerator.Term):
  """Representation of an individual NFT term.

     This is primarily useful for NewNftables.__str__() method.

     Args: term policy.Term object
  """

  _ALLOWED_PROTO_NAME = frozenset([
      'tcp', 'udp', 'icmp', 'esp', 'udp', 'ah', 'comp', 'udplite', 'dccp',
      'sctp', 'icmpv6'
  ])
  _ACTIONS = {
      'accept': 'allow',
      'deny': 'discard',
      'reject': 'say go away to',
      'next': 'pass it onto the next term',
      'reject-with-tcp-rst': 'reset'
  }

  def __init__(self, term, nf_af, nf_hook, verbose=True):
    """Individual instances of a Term for NFtables.

    Args:
      term: Term data.
      nf_af: nftables table type IPv4 only (ip), IPv6 (ip6) or dual-stack
        (inet).
      nf_hook: INPUT or OUTPUT (packet processing/direction of traffic).
      verbose: used for comment handling.
    """
    self.term = term
    self.address_family = nf_af
    self.hook = nf_hook
    self.verbose = verbose

  def CreateAnonymousSet(self, string_elements):
    """Build a nftables anonymous set from some elements.

    Anonymous are formatted using curly braces then some data. These sets are
    bound to a rule, have no specific name and cannot be updated.

    Args:
      string_elements: a list of strings to format.

    Returns:
      formatted string of items as anonymous set.
    """
    nfset = ''
    if len(string_elements) == 1:
      nfset = str(string_elements)
    if len(string_elements) > 1:
      nfset = ', '.join(string_elements)
    return '{{ %s }}' % nfset

  def _RulesetGenerator(self, term):
    """Generate string rules of a given Term.

    Rules are constructed from Terms() and are contained within chains.
    This function generates rules that will be present inside a regular
    (non-base) chain. Each item in list represents a line break for later
    parsing.

    Args:
      term: term data.

    Returns:
      list of strings. Representing a ruleset for later formatting.
    """
    term_ruleset = []
    src_addr_book = self._AddressClassifier(term.source_address)
    dst_addr_book = self._AddressClassifier(term.destination_address)

    def ICMP(nf_family, protocol, icmp_code, src_addr, dst_addr):
      """ICMP Term handling.

      Args:
        nf_family: nftables address family (ip, ip6, inet for mixed)
        protocol: list of protocols for term
        icmp_code: icmp specific option
        src_addr: source networks in dict[nf_family] format.
        dst_addr: destination networks in dict[nf_family] format.

      Returns:
        list of strings containing rule in specific format.
      """

    # COMMENT handling.
    if self.verbose:
      for line in self.term.comment:
        term_ruleset.append('comment "%s"' % line)

    # Protocol handling.
    # TODO(gfm): CL 2 handles protocols.

    # TODO(gfm): Handle rules with network addresses.
    return term_ruleset

  def _AddressClassifier(self, address_to_classify):
    """Organizes network addresses according to IP family in a dict.

    Args:
      address_to_classify: list of network addresses

    Returns:
      dictionary of network addresses classified by AF.
    """
    addresses = collections.defaultdict(list)
    for addr in address_to_classify:
      if addr.version == 4:
        addresses['ip'].append(addr)
      if addr.version == 6:
        addresses['ip6'].append(addr)
    return addresses

  def _Group(self, group):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of tuples
        (ports)

    Returns:
      rval: a string surrounded by '[' and ']'
    """

    def _FormatPorts(port):
      if isinstance(port, int):
        return str(port)
      elif port[0] == port[1]:
        return '%d' % port[0]
      else:
        # port range
        return '%d-%d' % (port[0], port[1])

    if len(group) > 1:
      rval = [_FormatPorts(x) for x in group]
    else:
      rval = _FormatPorts(group[0])
    return rval

  def __str__(self):
    """Terms printing function."""

    # Things we need to do in this section:
    # 1) validate term IPv4 or IPv6 = the family of the table its going in.
    # 2)
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'newnftables' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'newnftables' in self.term.platform_exclude:
        return ''

    # Terms printing.
    print('TERM = ', self.term)
    self._RulesetGenerator(self.term)

    # Create nftables IP family dictionaries.
    if self.term.source_address:
      source_addresses = self._AddressClassifier(self.term.source_address)
    if self.term.destination_address:
      destination_address = self._AddressClassifier(
          self.term.destination_address)

    return ''


class NewNftables(aclgenerator.ACLGenerator):
  """A NFtables policy object."""

  _PLATFORM = 'newnftables'
  SUFFIX = '.nft'
  _HEADER_AF = frozenset(('inet', 'inet6', 'mixed'))
  _SUPPORTED_HOOKS = frozenset(('input', 'output'))
  _HOOK_PRIORITY_DEFAULT = 0
  _BASE_CHAIN_PREFIX = 'root'  # TODO(gfm): will be changed.

  _OPTIONAL_SUPPORTED_KEYWORDS = frozenset([
      'expiration',
  ])

  # Below mapping converts capirca HEADER native to nftables table.
  # In Nftables 'inet' contains both IPv4 and IPv6 addresses and rules.
  NF_TABLE_AF_MAP = {'inet': 'ip', 'inet6': 'ip6', 'mixed': 'inet'}

  def _TranslatePolicy(self, pol, exp_info):
    """Translates a Capirca policy file into NFtables specific data structure.

    Reads a POL file, filters for NFTables specific data, parses each term
    and populates the nftables_policies list.

    Args:
      pol: A Policy() object representing a given POL file.
      exp_info: An int that specifies number of weeks until policy expires.

    Raises:
      TermError: Raised when policy term requirements are not met.
    """
    self.nftables_policies = []

    def ProcessHeader(header_options):
      """Capirca policy header processing.

      Args:
        header_options: capirca policy header data (filter_options)

      Raises:
        HeaderError: Raised when the policy header format requirements are not
        met.

      Returns:
        netfilter_family: x. filter_options[0]
        netfilter_hook: x. filter_options[1].lower()
        netfilter_priority: numbers = [x for x in filter_options if x.isdigit()]
        policy_default_action: nftable action to take on unmatched packets.
        verbose: header and term verbosity.
      """
      if len(header_options) < 2:
        raise HeaderError(
            'Invalid header for Nftables. Required fields missing.')
      # First header element should dictate type of policy.
      if header_options[0] not in NewNftables._HEADER_AF:
        raise HeaderError(
            'Invalid address family in header: %s. Supported: %s' %
            (header_options[0], NewNftables._HEADER_AF))
      netfilter_family = self.NF_TABLE_AF_MAP.get(header_options[0])
      policy_default_action = 'drop'
      if 'ACCEPT' in header_options:
        policy_default_action = 'accept'
      netfilter_hook = header_options[1].lower()
      if netfilter_hook not in self._SUPPORTED_HOOKS:
        raise HeaderError(
            '%s is not a supported nftables hook. Supported hooks: %s' %
            (netfilter_hook, list(self._SUPPORTED_HOOKS)))
      if len(header_options) >= 2:
        numbers = [x for x in header_options if x.isdigit()]
        if not numbers:
          netfilter_priority = self._HOOK_PRIORITY_DEFAULT
          logging.info(
              'INFO: NFtables priority not specified in header.'
              'Defaulting to %s', self._HOOK_PRIORITY_DEFAULT)
        if len(numbers) == 1:
          # A single integer value is used to set priority.
          netfilter_priority = numbers[0]
        if len(numbers) > 1:
          raise HeaderError('Too many integers in header.')
      verbose = True
      if 'noverbose' in header_options:
        verbose = False
        header_options.remove('noverbose')
      return netfilter_family, netfilter_hook, netfilter_priority, policy_default_action, verbose

    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions('newnftables')
      nf_af, nf_hook, nf_priority, filter_policy_default_action, verbose = ProcessHeader(
          filter_options)

      term_names = set()
      new_terms = []
      for term in terms:
        if term.name in term_names:
          raise TermError('Duplicate term name')
        term_names.add(term.name)
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info(
                'INFO: Term %s in policy %s expires '
                'in less than two weeks.', term.name, nf_af)
          if term.expiration <= current_date:
            logging.warning(
                'WARNING: Term %s in policy %s is expired and '
                'will not be rendered.', term.name, nf_af)
            continue
        # Handle address excludes before building nft address book dict.
        for i in term.source_address_exclude:
          term.source_address = nacaddr.RemoveAddressFromList(
              term.source_address, i)
        for i in term.destination_address_exclude:
          term.destination_address = nacaddr.RemoveAddressFromList(
              term.destination_address, i)
        new_terms.append(Term(term, nf_af, nf_hook, verbose))
      self.nftables_policies.append(
          (header, nf_af, nf_hook, nf_priority, filter_policy_default_action,
           verbose, new_terms))

  def __str__(self):
    """Render the policy as Nftables configuration."""
    self.tables = collections.defaultdict(list)
    self.chains = collections.defaultdict(list)
    nft_config = []

    # output = self._BuildTables(self.nftables_policies)
    for (header, nf_af, nf_hook, nf_priority, filter_policy_default_action,
         verbose, new_terms) in self.nftables_policies:
      base_chain_comment = ''
      # Add max character checking on header.comment later if needed.
      if verbose:
        base_chain_comment = header.comment
      self.tables[nf_af].append(
          (nf_hook, nf_priority, filter_policy_default_action,
           base_chain_comment, new_terms))

    for nf_af in self.tables:
      nft_config.append('table %s filtering_policies {' % nf_af)
      for count, elem in enumerate(self.tables[nf_af]):
        base_chain_name = self._BASE_CHAIN_PREFIX + str(count)

        nft_config.append('\tchain %s {' % base_chain_name)
        if str(elem[1]):
          nft_config.append('\t\tcomment "%s"' % elem[0][0])
        nft_config.append('\t\ttype filter hook %s priority %s; policy %s;' %
                          (elem[0], elem[1], elem[2]))
        base_chain_terms = elem[4]
        for valid_term in base_chain_terms:
          # Here we call Term(str)
          term_output = str(valid_term)
          if term_output:
            nft_config.append(term_output)
            print(term_output)  # space then term_rule.
        nft_config.append('\t}')  # chain_end
      nft_config.append('}')  # table_end

    return '\n '.join(nft_config)
