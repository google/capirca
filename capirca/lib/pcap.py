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
"""Pcap filter generator.

This generate a pcap packet filter expression that either:
  1) Matches (i.e., captures), the packets that match the ACCEPT clauses
     specified in a given policy, or
  2) Matches the packets that match opposite of that, i.e., the DENY or REJECT
     clauses.
Support tcp flags matching and icmptypes, including ipv6/icmpv6, but not much
else past the standard addres, port, and protocol conditions.

Note that this is still alpha and will likely require more testing prior to
having more confidence in it.

Stolen liberally from packetfilter.py.
"""

import datetime

from absl import logging
from capirca.lib import aclgenerator


class Error(Exception):
  """Base error class."""


class UnsupportedActionError(Error):
  """Raised when we see an unsupported action."""


class UnsupportedTargetOptionError(Error):
  """Raised when we see an unsupported option."""


class Term(aclgenerator.Term):
  """Generate pcap filter to match a policy term."""

  _PLATFORM = 'pcap'
  _ACTION_TABLE = {
      'accept': '',
      'deny': '',
      'reject': '',
      'next': '',
      }

  _TCP_FLAGS_TABLE = {
      'syn': 'tcp-syn',
      'ack': 'tcp-ack',
      'fin': 'tcp-fin',
      'rst': 'tcp-rst',
      'urg': 'tcp-urg',
      'psh': 'tcp-push',
      'all': '(tcp-syn|tcp-ack|tcp-fin|tcp-rst|tcp-urg|tcp-push)',
      'none': '(tcp-syn&tcp-ack&tcp-fin&tcp-rst&tcp-urg&tcp-push)',
      }

  _PROTO_TABLE = {
      'ah': 'proto \\ah',
      'esp': 'proto \\esp',
      'icmp': 'proto \\icmp',
      'icmpv6': 'icmp6',
      'ip': 'proto \\ip',
      'ip6': 'ip6',
      'igmp': 'proto \\igmp',
      'igrp': 'igrp',
      'pim': 'proto \\pim',
      'tcp': 'proto \\tcp',
      'udp': 'proto \\udp',
      # bpf supports "\vrrp", but some winpcap version dont' recognize it,
      # so use the IANA protocol number for it:
      'vrrp': 'proto 112',
      'hopopt': 'ip6 protochain 0',
      }

  def __init__(self, term, filter_name, af='inet', direction=''):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in packetfilter.
      filter_name: The name of the filter chan to attach the term to.
      af: Which address family ('inet' or 'inet6') to apply the term to.
      direction: Direction of the flow.

    Raises:
      aclgenerator.UnsupportedFilterError: Filter is not supported.
    """
    super().__init__(term)
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.options = []
    self.default_action = 'deny'
    self.af = af
    self.direction = direction

  def __str__(self):
    """Render config output from this term object."""
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    conditions = []

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action
    if str(self.term.action[0]) not in self._ACTION_TABLE:
      raise aclgenerator.UnsupportedFilterError('%s %s %s %s' % (
          '\n', self.term.name, self.term.action[0],
          'action not currently supported.'))

    # source address
    term_saddrs = self._CheckAddressAf(self.term.source_address)
    if not term_saddrs:
      logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                   direction='source',
                                                   af=self.af))
      return ''

    conditions.append(self._GenerateAddrStatement(
        term_saddrs, self.term.source_address_exclude))

    # destination address
    term_daddrs = self._CheckAddressAf(self.term.destination_address)
    if not term_daddrs:
      logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                   direction='destination',
                                                   af=self.af))
      return ''

    conditions.append(self._GenerateAddrStatement(
        term_daddrs, self.term.destination_address_exclude))

    # protocol
    if self.term.protocol_except:
      raise aclgenerator.UnsupportedFilterError('%s %s %s' % (
          '\n', self.term.name,
          'protocol_except logic not currently supported.'))
    conditions.append(self._GenerateProtoStatement(self.term.protocol))

    conditions.append(self._GeneratePortStatement(
        self.term.source_port, 'src'))
    conditions.append(self._GeneratePortStatement(
        self.term.destination_port, 'dst'))

    # icmp-type
    icmp_types = ['']
    if self.term.icmp_type:
      if self.term.protocol == ['icmp']:
        af = 'inet'
      elif self.term.protocol == ['icmpv6']:
        af = 'inet6'
      else:
        raise aclgenerator.UnsupportedFilterError(
            '%s %s %s' % ('\n', self.term.name,
                          'icmp protocol is not defined or not supported.'))
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, af)

      if 'icmp' in self.term.protocol:
        conditions.append(self._GenerateIcmpType(icmp_types,
                                                 self.term.icmp_code))

    # tcp options
    if 'tcp' in self.term.protocol:
      conditions.append(self._GenerateTcpOptions(self.term.option))

    cond = Term.JoinConditionals(conditions, 'and')

    # Note that directionally-based pcap filter requires post-processing to
    # replace 'localhost' with whatever the IP(s) of the local machine happen
    # to be.  This bit of logic ensure there's a placeholder with the
    # appropriate booleans around it.  We also have to check that there exists
    # some form of condition already, else we'll end up with something overly
    # broad like 'dst net localhost' (e.g., 'default-deny').
    if cond and self.direction == 'in':
      cond = Term.JoinConditionals(['dst net localhost', cond], 'and')
    elif cond and self.direction == 'out':
      cond = Term.JoinConditionals(['src net localhost', cond], 'and')

    return cond + '\n'

  def _CheckAddressAf(self, addrs):
    """Verify that the requested address-family matches the address's family."""
    if not addrs:
      return ['any']
    if self.af == 'mixed':
      return addrs
    af_addrs = []
    af = self.NormalizeAddressFamily(self.af)
    for addr in addrs:
      if addr.version == af:
        af_addrs.append(addr)
    return af_addrs

  @staticmethod
  def JoinConditionals(condition_list, operator):
    """Join conditionals using the specified operator.

    Filters out empty elements and blank strings.

    Args:
      condition_list:  a list of str()-able items to join.
      operator:  the join string.

    Returns:
      A string consisting of the joined elements.  If all elements are False
      or whitespace-only, the empty string.
    """
    condition_list = [_f for _f in condition_list if _f]
    condition_list = [str(x).strip(' ') for x in condition_list
                      if str(x).strip()]
    if not condition_list:
      return ''

    op = ' %s ' % (operator)
    res = '(%s)' % (op.join(condition_list))
    return res

  def _GenerateAddrStatement(self, addrs, exclude_addrs):
    addrlist = []
    for d in addrs:
      if d != 'any' and str(d) != '::/0':
        addrlist.append('dst net %s' % (d))

    excludes = []
    if exclude_addrs:
      for d in exclude_addrs:
        if d != 'any' and str(d) != '::/0':
          excludes.append('not dst net %s' % (d))
        else:
          # excluding 'any' doesn't really make sense ...
          return ''

    if excludes:
      return Term.JoinConditionals(
          [Term.JoinConditionals(addrlist, 'or'),
           Term.JoinConditionals(excludes, 'or')], 'and not')
    else:
      return Term.JoinConditionals(addrlist, 'or')

  def _GenerateProtoStatement(self, protocols):
    return Term.JoinConditionals(
        [self._PROTO_TABLE[p] for p in protocols], 'or')

  def _GeneratePortStatement(self, ports, direction):
    conditions = []
    # term.destination_port is a list of tuples containing the start and end
    # ports of the port range.  In the event it is a single port, the start
    # and end ports are the same.
    for port_tuple in ports:
      if port_tuple[0] == port_tuple[1]:
        conditions.append('%s port %s' % (direction, port_tuple[0]))
      else:
        conditions.append('%s portrange %s-%s' % (
            direction, port_tuple[0], port_tuple[1]))
    return Term.JoinConditionals(conditions, 'or')

  def _GenerateTcpOptions(self, options):
    opts = [str(x) for x in options]
    tcp_flags_set = []
    tcp_flags_check = []
    for next_opt in opts:
      if next_opt == 'tcp-established':
        tcp_flags_set.append(self._TCP_FLAGS_TABLE['ack'])
        tcp_flags_check.extend([self._TCP_FLAGS_TABLE['ack']])

      else:
        # Iterate through flags table, and create list of tcp-flags to append
        for next_flag in self._TCP_FLAGS_TABLE:
          if next_opt.find(next_flag) == 0:
            tcp_flags_check.append(self._TCP_FLAGS_TABLE.get(next_flag))
            tcp_flags_set.append(self._TCP_FLAGS_TABLE.get(next_flag))

    if tcp_flags_check:
      return '(tcp[tcpflags] & (%s) == (%s))' % ('|'.join(tcp_flags_check),
                                                 '|'.join(tcp_flags_set))
    return ''

  def _GenerateIcmpType(self, icmp_types, icmp_code):
    rtr_str = ''
    if icmp_types:
      code_strings = ['']
      if icmp_code:
        code_strings = [' and icmp[icmpcode] == %d' % code for
                        code in icmp_code]
      rtr_str = Term.JoinConditionals(
          ['icmp[icmptype] == %d%s' % (x, y) for y in code_strings for
           x in icmp_types], 'or')
    return rtr_str


class PcapFilter(aclgenerator.ACLGenerator):
  """Generates filters and terms from provided policy object.

  Note that since pcap isn't actually a firewall grammar, this generates a
  filter that only matches matches that which would be accepted by the
  specified policy.
  """

  _PLATFORM = 'pcap'
  _DEFAULT_PROTOCOL = 'all'
  SUFFIX = '.pcap'
  _TERM = Term

  def __init__(self, *args, **kwargs):
    """Initialize a PcapFilter generator.

    Takes standard ACLGenerator arguments, as well as an 'invert' kwarg.  If
    this argument is true, the pcap filter will be reversed, such that it
    matches all those packets that would be denied by the specified policy.

    Args:
      *args: Arguments.
      **kwargs: Keyword arguments.

    """
    self._invert = False
    if 'invert' in kwargs:
      self._invert = kwargs['invert']
      del kwargs['invert']
    super().__init__(*args, **kwargs)

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'logging', 'icmp_code'}
    supported_tokens -= {'verbatim'}

    supported_sub_tokens.update(
        {'action': {'accept', 'deny', 'reject', 'next'},
         'option': {
             'tcp-established',
             'established',
             'syn',
             'ack',
             'fin',
             'rst',
             'urg',
             'psh',
             'all',
             'none'},
        })

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.pcap_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    good_afs = ['inet', 'inet6', 'mixed']
    good_options = ['in', 'out']
    direction = ''

    for header, terms in pol.filters:
      filter_type = None
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)[1:]
      filter_name = header.FilterName(self._PLATFORM)

      # ensure all options after the filter name are expected
      for opt in filter_options:
        if opt not in good_afs + good_options:
          raise UnsupportedTargetOptionError('%s %s %s %s' % (
              '\nUnsupported option found in', self._PLATFORM,
              'target definition:', opt))

      if 'in' in filter_options:
        direction = 'in'
      elif 'out' in filter_options:
        direction = 'out'

      # Check for matching af
      for address_family in good_afs:
        if address_family in filter_options:
          # should not specify more than one AF in options
          if filter_type is not None:
            raise aclgenerator.UnsupportedFilterError('%s %s %s %s' % (
                '\nMay only specify one of', good_afs, 'in filter options:',
                filter_options))
          filter_type = address_family
      if filter_type is None:
        filter_type = 'mixed'

      # add the terms
      accept_terms = []
      deny_terms = []
      term_names = set()
      for term in terms:
        if term.name in term_names:
          raise aclgenerator.DuplicateTermError(
              'You have a duplicate term: %s' % term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue

        if not term:
          continue

        if term.action[0] == 'accept':
          accept_terms.append(self._TERM(term, filter_name, filter_type,
                                         direction))
        elif term.action[0] == 'deny' or term.action[0] == 'reject':
          deny_terms.append(self._TERM(term, filter_name, filter_type,
                                       direction))

      self.pcap_policies.append((header, filter_name, filter_type, accept_terms,
                                 deny_terms))

  def __str__(self):
    """Render the output of the PF policy into config."""
    target = []

    for (unused_header, unused_filter_name, unused_filter_type, accept_terms,
         deny_terms) in self.pcap_policies:

      accept = []
      for term in accept_terms:
        term_str = str(term)
        if term_str:
          accept.append(str(term))
      accept_clause = Term.JoinConditionals(accept, 'and')

      deny = []
      for term in deny_terms:
        term_str = str(term)
        if term_str:
          deny.append(str(term))
      deny_clause = Term.JoinConditionals(deny, 'and')

      if self._invert:
        target.append(
            Term.JoinConditionals([deny_clause, accept_clause], 'and not'))
      else:
        target.append(
            Term.JoinConditionals([accept_clause, deny_clause], 'and not'))

    return '\nor\n'.join(target) + '\n'
