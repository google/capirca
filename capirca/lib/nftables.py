# Copyright 2023 Google Inc. All Rights Reserved.
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
import copy
import datetime
import logging

from capirca.lib import aclgenerator
from capirca.lib import nacaddr

# NFTables and capirca have conflicting definitions of 'address family'
# In capirca:
# 'mixed' refers to a 'mixed address policy IPv4/IPv6'
# 'inet6' refers to IPv6 only.
# 'inet' refers to IPv4 only.
# In nftables:
# 'inet' refers to mixed IPv4/IPv6 policies.
# 'ip6' IPv6 only.
# 'ip' IPv4 only.
# Therefore; we use static global variables in this generator to refer to the
# real intent, values are the NFtable AF format.
ip4 = 'ip'
ip6 = 'ip6'
mixed = 'inet'


def TabSpacer(number_spaces, string):
  """Configuration indentation utility function."""
  blank_space = ' '
  return (blank_space * number_spaces) + string


def Add(statement):
  """Prefix space appending utility to handle text joins."""
  if statement:
    return TabSpacer(1, statement)
  else:
    return statement


def ChainFormat(kind, name, ruleset):
  """Builds a chain in NFtables configuration format.

  Args:
    kind: type string (chain or counter)
    name: name to give the chain.
    ruleset: the list returned from RulesetGenerator function.

  Returns:
    chain_strings: multi-line string nftable configuration for the chain.
  """
  header_sp = 4
  content_sp = 8
  chain_output = []
  chain_output.append(TabSpacer(header_sp, '%s %s {' % (kind, name)))
  for line in ruleset:
    chain_output.append(TabSpacer(content_sp, line))
  chain_output.append(TabSpacer(header_sp, '}'))
  return '\n'.join(chain_output)


class Error(Exception):
  """Base error class."""


class TermError(Error):
  """Raised when a term is not valid."""


class HeaderError(Error):
  """Raised when a header is not valid."""


class UnsupportedFilterTypeError(Error):
  """Raised when an unsupported filter type is specified."""


class UnsupportedExpressionError(Error):
  """Raised when an unsupported expression is specified."""


class Term(aclgenerator.Term):
  """Representation of an individual NFT term.

     This is primarily useful for Nftables.__str__() method.

     Args: term policy.Term object
  """

  _ALLOWED_PROTO_NAME = frozenset([
      'tcp', 'udp', 'icmp', 'esp', 'udp', 'ah', 'comp', 'udplite', 'dccp',
      'sctp', 'icmpv6'
  ])
  _ACTIONS = {'accept': 'accept', 'deny': 'drop'}

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

  def MapICMPtypes(self, af, term_icmp_types):
    """Normalize certain ICMP_TYPES for NFTables rendering.

    If we encounter certain keyword values in policy.Term.ICMP_TYPE keywords,
    we override them with NFTable specific values in order for rendered
    policy to be semantically correct with what NFT expects.
    https://www.netfilter.org/projects/nftables/manpage.html

    Function is used inside PortsAndProtocols.

    Args:
      af: address family.
      term_icmp_types: ICMP types keywords.

    Returns:
      normalized list of icmp_types.
    """
    ICMP_TYPE_REMAP = {
        6: {
            'multicast-listener-query': 'mld-listener-query',
            'multicast-listener-report': 'mld-listener-report',
            'multicast-listener-done': 'mld-listener-done',
            'router-solicit': 'nd-router-solicit',
            'router-advertisement': 'nd-router-advert',
            'neighbor-solicit': 'nd-neighbor-solicit',
            'neighbor-advertisement': 'nd-neighbor-advert',
            'redirect-message': 'nd-redirect',
            'inverse-neighbor-discovery-solicitation': 'ind-neighbor-solicit',
            'inverse-neighbor-discovery-advertisement': 'ind-neighbor-advert',
            'version-2-multicast-listener-report': 'mld2-listener-report',
        },
        4: {
            # IPv4 exceptions below
            'unreachable': 'destination-unreachable',
            'information-request': 'info-request',
            'information-reply': 'info-reply',
            'mask-request': 'address-mask-request',
            'mask-reply': 'address-mask-reply',
        }
    }

    for item in term_icmp_types:
      if af == ip4:
        # IPv4 ICMP
        if item in ICMP_TYPE_REMAP[4]:
          # Replace with NFT expected value.
          term_icmp_types[term_icmp_types.index(item)] = ICMP_TYPE_REMAP[4].get(
              item)
      if af == ip6:
        # IPv6 ICMP
        if item in ICMP_TYPE_REMAP[6]:
          # Replace with NFT expected value.
          term_icmp_types[term_icmp_types.index(item)] = ICMP_TYPE_REMAP[6].get(
              item)
    return term_icmp_types

  def CreateAnonymousSet(self, data):
    """Build a nftables anonymous set from some elements.

    Anonymous are formatted using curly braces then some data. These sets are
    bound to a rule, have no specific name and cannot be updated.

    Args:
      data: a list of strings to format.

    Returns:
      formatted string of items as anonymous set.
    """
    nfset = []
    if isinstance(data, str):
      # Handle single string. No params.
      return data
    if len(data) == 1:
      # Handle a list of a single element.
      nfset = data[0]
      return nfset
    if len(data) > 1:
      nfset = ', '.join(data)
      return '{{ {0} }}'.format(nfset)

  def PortsAndProtocols(self, address_family, protocol, src_ports, dst_ports,
                        icmp_type):
    """Handling protocol specific NFTable statements.

    Args:
      address_family: term address family.
      protocol: term protocol.
      src_ports: raw term source port.
      dst_ports: raw term dest port.
      icmp_type: special ICMP type flag.

    Returns:
      list of statements related to ports and protocols.
    """

    def PortStatement(protocol, source, destination):
      """NFT port statement. Returns empty if no ports defined."""
      ports_list = []

      # SOURCE PORTS.
      if source:
        ports_list.append('%s sport %s' %
                          (protocol, self.CreateAnonymousSet(source)))

      # DESTINATION PORTS.
      if destination:
        ports_list.append('%s dport %s' %
                          (protocol, self.CreateAnonymousSet(destination)))

      # Normalize ports into single nft statement.
      if ports_list:
        ports_statement = ' '.join(ports_list)
      else:
        ports_statement = ''
      return ports_statement  # end PortStatement.

    ip_protocol = copy.deepcopy(protocol)
    ip6_protocol = copy.deepcopy(protocol)
    # Normalize term.ports objects.
    src_p = self._Group(src_ports)
    dst_p = self._Group(dst_ports)
    statement_lines = []

    # Normalize ICMP types.
    # TODO: Call self.NormalizeIcmpTypes.
    icmp_type = self.MapICMPtypes(address_family, icmp_type)

    if address_family == 'ip':
      # IPv4 stuff.
      if icmp_type and ('icmp' in ip_protocol):
        if len(icmp_type) > 1:
          statement_lines.append('icmp type' +
                                 Add(self.CreateAnonymousSet(icmp_type)))
        else:
          statement_lines.append('icmp type' + Add(icmp_type))
        ip_protocol.remove('icmp')
      if 'icmpv6' in ip_protocol:
        # No IPv6 protocols in IPv4 family.
        ip_protocol.remove('icmpv6')
      if ip_protocol:
        # Multi-protocol and zero-ports.
        if len(ip_protocol) > 1 and not (src_ports and dst_ports):
          statement_lines.append('ip protocol' +
                                 Add(self.CreateAnonymousSet(ip_protocol)))
        else:
          for proto in ip_protocol:
            if (src_ports and dst_ports):
              statement_lines.append(PortStatement(proto, src_p, dst_p))
            else:
              statement_lines.append('ip protocol' + Add(proto))

    if address_family == 'ip6':
      # IPv6 stuff.
      if icmp_type and ('icmpv6' in ip6_protocol):
        if len(icmp_type) > 1:
          statement_lines.append('icmpv6 type' +
                                 Add(self.CreateAnonymousSet(icmp_type)))
        else:
          statement_lines.append('icmpv6 type' + Add(icmp_type))
        ip6_protocol.remove('icmpv6')
      if 'icmp' in ip6_protocol:
        # No IPv4 protocols in IPv6 family.
        ip6_protocol.remove('icmp')
      if ip6_protocol:
        # NFT IPv6 protocol matching is complex. Using 'ip6 nexthdr' only
        # matches if ipv6 packet does not contain any extension headers.
        # we use meta l4proto here to walk down the headers until real transport
        # protocol is found. This allows us to use Sets here too.
        # https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers
        if len(ip6_protocol) > 1 and not (src_ports and dst_ports):
          statement_lines.append('meta l4proto' +
                                 Add(self.CreateAnonymousSet(ip6_protocol)))
        else:
          # We avoid using th (transport header), instead we use single
          # statements for each protocol.
          for proto in ip6_protocol:
            if (src_ports or dst_ports):
              statement_lines.append(PortStatement(proto, src_p, dst_p))
            else:
              # Single proto, no ports.
              statement_lines.append('meta l4proto' + Add(proto))

    return statement_lines

  def _OptionsHandler(self, term):
    """Term 'option' handler.

    Function used to evaluate term.logging and also term.option values. Then
    it builds any statement that would be appended before a veredict.
    Results of this function are then used in GroupExpressions() to combine
    a final valid NFTables chain.

    Args:
      term: capirca Term data.

    Returns:
      list of statements related to generator options.
    """
    options = []

    # Stateful firewall, Accept only NEW traffic for the specific term.
    # Base chain already allows all return traffic of
    # state (ESTABLISHED, RELATED)
    # This should prevent invalid, untracked packets from being accepted.
    if 'deny' not in term.action and not term.icmp_type:
      options.append('ct state new')

    # 'logging' handling.
    if term.logging:
      # str() trick to circumvent VarType class attr comparison checks.
      if 'disable' not in str(term.logging):
        # Simple syslogging implementation.
        options.append('log prefix "%s"' % term.name)

    # 'counter' handling.
    # https://wiki.nftables.org/wiki-nftables/index.php/Counters
    # We don't use named counters here because we already structure NFT ruleset
    # in child chains per each rule. So simply looking at term_child_chain is
    # easy to tell the counter stats for that ruleset.
    if term.counter:
      options.append('counter')

    # Build the final statement to be returned.
    if options:
      return ' '.join(options)
    else:
      return ''

  def GroupExpressions(
      self, int_expr, address_expr, pp_expr, options, verdict, comment
  ):
    """Combines all expressions with a verdict (decision).

    The inputs are already pre-sanitized by RulesetGenerator. NFTables processes
    rules from left-to-right - ending in a verdict. We form our ruleset then
    towards the end append any term.options from _OptionsHandler.

    Args:
      int_expr: RulesetGenerator source or destination interface str.
      address_expr: pre-processed list of nftable statements of network
        addresses.
      pp_expr: pre-processed list of nftables protocols and ports.
      options: string value to append before verdict for NFT special options.
      verdict: action to take on resulting final statement (allow/deny).
      comment: term.comment string adhering to NFT limits.

    Returns:
      list of strings representing valid nftables statements.
    """
    statement = []
    if address_expr:
      for addr in address_expr:
        if pp_expr:
          for pstat in pp_expr:
            if pstat.startswith('icmp type') or addr.startswith('ip '):
              # Handle IPv4 ports and proto statements.
              if addr.startswith('ip '):
                statement.append(addr + Add(pstat) + Add(options) +
                                 Add(verdict))
            elif pstat.startswith('icmpv6 type') or addr.startswith('ip6'):
              if addr.startswith('ip6'):
                statement.append(addr + Add(pstat) + Add(options) +
                                 Add(verdict))
        else:
          statement.append(addr + Add(options) + Add(verdict))
    elif pp_expr:
      # Handle statement without addresses but has ports & protocols.
      for pstat in pp_expr:
        statement.append(pstat + Add(options) + Add(verdict))
    else:
      # If no addresses or ports & protocol. Verdict only statement.
      statement.append((Add(options) + Add(verdict)))
    # source/destination interface handling always to be done at the end.
    if int_expr:
      # 'statement' is a list because join to another list in RulesetGenerator.
      statement[0] = int_expr + Add(statement[0])
    # Handling of comments should always be done after verdict statement.
    if comment:
      statement[0] = statement[0] + Add(comment)
    return statement

  def _AddrStatement(self, address_family, src_addr, dst_addr):
    """Builds an NFTables address statement.

    Args:
      address_family: NFTables address family.
      src_addr: prefiltered list of src addresses.
      dst_addr: prefiltered list of dst addresses.

    Returns:
      list of strings representing valid nftables address statements (IPv4/6).
    """
    address_statement = []
    src_addr_book = self._AddressClassifier(src_addr)
    dst_addr_book = self._AddressClassifier(dst_addr)

    if src_addr and dst_addr:
      # Condition where term has both defined.
      if address_family == 'ip':
        if src_addr_book['ip'] and dst_addr_book['ip']:
          address_statement.append(
              'ip saddr ' + self.CreateAnonymousSet(src_addr_book['ip']) + ' ' +
              'ip daddr ' + self.CreateAnonymousSet(dst_addr_book['ip']))
      if address_family == 'ip6':
        if src_addr_book['ip6'] and dst_addr_book['ip6']:
          address_statement.append(
              'ip6 saddr ' + self.CreateAnonymousSet(src_addr_book['ip6']) +
              ' ' + 'ip6 daddr ' +
              self.CreateAnonymousSet(dst_addr_book['ip6']))
    elif src_addr:
      # Term has only src defined.
      if address_family == 'ip':
        if src_addr_book['ip']:
          address_statement.append('ip saddr ' +
                                   self.CreateAnonymousSet(src_addr_book['ip']))
      if address_family == 'ip6':
        if src_addr_book['ip6']:
          address_statement.append(
              'ip6 saddr ' + self.CreateAnonymousSet(src_addr_book['ip6']))
    elif dst_addr:
      if address_family == 'ip':
        if dst_addr_book['ip']:
          address_statement.append('ip daddr ' +
                                   self.CreateAnonymousSet(dst_addr_book['ip']))
      if address_family == 'ip6':
        if dst_addr_book['ip6']:
          address_statement.append(
              'ip6 daddr ' + self.CreateAnonymousSet(dst_addr_book['ip6']))
    return address_statement

  def RulesetGenerator(self, term):
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
    unique_term_ruleset = []
    comment = ''

    # COMMENT handling.
    if self.verbose:
      comment = 'comment ' + aclgenerator.TruncateWords(
          self.term.comment, Nftables.COMMENT_CHAR_LIMIT)

    # INTERFACE (source/destination) handling.
    if term.source_interface:
      interface = 'iifname' + Add(term.source_interface)
    elif term.destination_interface:
      interface = 'oifname' + Add(term.destination_interface)
    else:
      interface = ''
    # OPTIONS / LOGGING / COUNTERS
    opt = self._OptionsHandler(term)
    # STATEMENT VERDICT / ACTION.
    verdict = self._ACTIONS[self.term.action[0]]

    address_families = [self.address_family
                       ] if self.address_family != mixed else [ip4, ip6]
    for address_family in address_families:
      # ADDRESS handling.
      address_list = self._AddrStatement(address_family,
                                         self.term.source_address,
                                         self.term.destination_address)
      # Check if we're dealing with a term of a different IP family that needs
      # to be skipped.
      if not address_list and (
          self.term.source_address or self.term.destination_address):
        continue

      # PORTS and PROTOCOLS handling.
      proto_and_ports = self.PortsAndProtocols(address_family,
                                               self.term.protocol,
                                               self.term.source_port,
                                               self.term.destination_port,
                                               self.term.icmp_type)
      # Do not render ICMP types if IP family mismatch.
      if ((address_family == 'ip6' and 'icmp' in self.term.protocol) or
          (address_family == 'ip' and ('icmpv6' in self.term.protocol)
           or 'icmp6' in self.term.protocol)):
        continue

      # TODO: If verdict is not supported, drop nftable_rule for it.
      nftable_rule = self.GroupExpressions(
          interface, address_list, proto_and_ports, opt, verdict, comment
      )
      term_ruleset.extend(nftable_rule)
    # Ensure that chain statements contain no duplicates rules.
    unique_term_ruleset = [
        i for n, i in enumerate(term_ruleset) if i not in term_ruleset[:n]]
    return unique_term_ruleset

  def _AddressClassifier(self, address_to_classify):
    """Organizes network addresses according to IP family in a dict.

    Args:
      address_to_classify: nacaddr.IP list of network addresses.

    Returns:
      dictionary of network addresses classified by AF.
    """
    addresses = collections.defaultdict(list)
    for addr in address_to_classify:
      if addr.version == 4:
        addresses['ip'].append(str(addr))
      if addr.version == 6:
        addresses['ip6'].append(str(addr))
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
    elif len(group) == 1:
      rval = _FormatPorts(group[0])
    else:
      # Ports undefined/empty.
      rval = ''
    return rval

  def __str__(self):
    """Terms printing function.

    Each term is expressed as its own chain. Later referenced to a parent chain
    with filter directionality (input/output).
    """
    if self.term.platform:
      if 'nftables' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'nftables' in self.term.platform_exclude:
        return ''
    return ChainFormat('chain', self.term.name,
                       self.RulesetGenerator(self.term))


class Nftables(aclgenerator.ACLGenerator):
  """A NFtables policy object."""

  _PLATFORM = 'nftables'
  SUFFIX = '.nft'
  _HEADER_AF = frozenset(('inet', 'inet6', 'mixed'))
  _SUPPORTED_HOOKS = frozenset(('input', 'output'))
  _HOOK_PRIORITY_DEFAULT = 0
  _BASE_CHAIN_PREFIX = 'root'
  _LOGGING = set()

  _OPTIONAL_SUPPORTED_KEYWORDS = frozenset([
      'expiration',
  ])

  COMMENT_CHAR_LIMIT = 126

  _AF_MAP = {'inet': (4,), 'inet6': (6,), 'mixed': (4, 6)}
  # Below mapping converts capirca HEADER native to nftables table.
  # In Nftables 'inet' contains both IPv4 and IPv6 addresses and rules.
  NF_TABLE_AF_MAP = {'inet': 'ip', 'inet6': 'ip6', 'mixed': 'inet'}

  def _BuildTokens(self):
    """NFTables generator list of supported tokens and sub tokens.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()
    # Set of supported keywords for a given platform.  Values should be in
    # undercase form, eg, icmp_type (not icmp-type)
    supported_tokens = {
        'action',
        'comment',
        'destination_address',
        'destination_address_exclude',
        'destination_port',
        'expiration',
        'icmp_type',
        'name',  # obj attribute, not token
        'option',
        'protocol',
        'platform',
        'platform_exclude',
        'source_interface', # NFT iifname
        'source_address',
        'source_address_exclude',
        'source_port',
        'destination_interface', # NFT oifname
        'translated',  # obj attribute, not token
        'stateless_reply',
    }

    # These keys must be also listed in supported_tokens.
    # Keys should be in undercase form, eg, icmp_type (not icmp-type). Values
    # should be in dash form, icmp-type (not icmp_type)
    supported_sub_tokens = {
        'option': {
            'established',
            'tcp-established',
        },
        'action': {
            'accept',
            'deny',
        },
        'icmp_type':
            set(
                list(Term.ICMP_TYPE[4].keys()) + list(Term.ICMP_TYPE[6].keys()))
    }
    return supported_tokens, supported_sub_tokens

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

    pol_counter = 0

    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions('nftables')
      nf_af, nf_hook, nf_priority, filter_policy_default_action, verbose = self._ProcessHeader(
          filter_options)

      # Base chain determine name based on iteration of header.
      base_chain_name = self._BASE_CHAIN_PREFIX + str(pol_counter)
      child_chains = collections.defaultdict(dict)
      term_names = set()
      new_terms = []
      for term in terms:
        if term.name in term_names:
          raise TermError('Duplicate term name')
        term_names.add(term.name)
        if term.source_interface and term.destination_interface:
          raise TermError(
              'Incorrect interface on term. Must be either be a source or'
              ' destination, not both.'
          )
          continue
        if term.stateless_reply:
          logging.warning(
              'WARNING: Term %s is a stateless reply '
              'term and will not be rendered.', term.name)
          continue
        # This generator is stateful, we don't do stateless rules.
        # Stateful firewalls don't require a reverse rule/term; thus skip.
        if 'established' in term.option:
          logging.warning(
              'WARNING: Term %s is a established '
              'term and will not be rendered.', term.name)
          continue
        if 'tcp-established' in term.option:
          logging.warning(
              'WARNING: Term %s is a tcp-established '
              'term and will not be rendered.', term.name)
          continue
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
        # Instantiate object to call function from Term()
        term_object = Term(term, nf_af, nf_hook, verbose)
        child_chains[base_chain_name].update(
            {term.name: term_object.RulesetGenerator(term)})
      pol_counter += 1
      self.nftables_policies.append(
          (header, base_chain_name, nf_af, nf_hook, nf_priority,
           filter_policy_default_action, verbose, child_chains))

  def _ProcessHeader(self, header_options):
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
      raise HeaderError('Invalid header for Nftables. Required fields missing.')
    # First header element should dictate type of policy.
    if header_options[0] not in Nftables._HEADER_AF:
      raise HeaderError('Invalid address family in header: %s. Supported: %s' %
                        (header_options[0], Nftables._HEADER_AF))
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

  def _ConfigurationDictionary(self, nft_pol):
    """NFTables configuration object.

    Organizes policies into a data structure that can keep relationships with
    NFTables address family (tables) and the parent base chain (+ child chains).

    Args:
      nft_pol: Object containing pre-processed data from _TranslatePolicy.

    Returns:
      nftables: dictionary of dictionaries NFTables policy object.
    """
    nftables = collections.defaultdict(dict)
    for (header, base_chain_name, nf_af, nf_hook, nf_priority,
         filter_policy_default_action, verbose, child_chains) in nft_pol:
      base_chain_comment = ''
      # TODO: If child_chain ruleset is empty don't store term.
      if verbose:
        base_chain_comment = header.comment
      nftables[nf_af][base_chain_name] = {
          'hook': nf_hook,
          'comment': base_chain_comment,
          'priority': nf_priority,
          'policy': filter_policy_default_action,
          'rules': child_chains,
      }
    return nftables

  def __str__(self):
    """Render the policy as Nftables configuration."""
    nft_config = []
    configuration = self._ConfigurationDictionary(self.nftables_policies)

    for address_family in configuration:
      nft_config.append('table %s filtering_policies {' % address_family)
      base_chain_dict = configuration[address_family]
      for item in base_chain_dict:
        # TODO: If we ever add NFTables 'named counters' it would go here.
        for k, v in base_chain_dict[item]['rules'][item].items():
          nft_config.append(ChainFormat('chain', k, v))
        # base chain header and contents.
        nft_config.append(TabSpacer(4, 'chain %s {' % item))
        if base_chain_dict[item]['comment']:
          # Due to Nftables limits on comments, we handle this twice.
          # First time we comment it out so .nft file is human-readable.
          nft_config.append(
              TabSpacer(8, '#' + ' '.join(base_chain_dict[item]['comment'])))
        nft_config.append(
            TabSpacer(
                8, 'type filter hook %s priority %s; policy %s;' %
                (base_chain_dict[item]['hook'],
                 base_chain_dict[item]['priority'],
                 base_chain_dict[item]['policy'])))
        # Add policy header comment after stateful firewall rule.
        if base_chain_dict[item]['comment']:
          nft_config.append(TabSpacer(8, 'ct state established,related accept'
                                      + Add('comment') +
                                      Add(aclgenerator.TruncateWords(
                                          base_chain_dict[item]['comment'],
                                          self.COMMENT_CHAR_LIMIT))))
        else:
          # stateful firewall: allows reply traffic.
          nft_config.append(TabSpacer(8, 'ct state established,related accept'))
        # Reference the child chains with jump.
        for child_chain in base_chain_dict[item]['rules'][item].keys():
          nft_config.append(TabSpacer(8, 'jump %s' % child_chain))
        nft_config.append(TabSpacer(4, '}'))  # chain_end
      nft_config.append('}')  # table_end

    # Terminating newline.
    nft_config.append('\n')
    return '\n'.join(nft_config)
