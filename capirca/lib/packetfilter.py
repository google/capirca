# Copyright 2012 Google Inc. All Rights Reserved.
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

"""PacketFilter (PF) generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import copy
import datetime

from capirca.lib import aclgenerator
from absl import logging


class Error(Exception):
  """Base error class."""


class DuplicateTermError(Error):
  """Raised when duplication of term names are detected."""


class DuplicateShortenedTableName(Error):
  """Raised when a duplicate shortened table name is found."""


class UnsupportedProtoError(Error):
  """Raised when a protocol is not supported."""


class Term(aclgenerator.Term):
  """Generate PacketFilter policy terms."""

  # Validate that term does not contain any fields we do not
  # support.  This prevents us from thinking that our output is
  # correct in cases where we've omitted fields from term.
  _PLATFORM = 'packetfilter'
  _ACTION_TABLE = {
      'accept': 'pass',
      'deny': 'block drop',
      'reject': 'block return',
      'next': 'pass',
      }
  # Moving the log keyword into an member variable allows subclasses to override
  # it to support logging options outside of the scope of the capirca policy
  # spec, e.g., on platform-specific options such as packetfilter's
  # "log (all, to pflogN)" per-direction.
  _LOG_TABLE = {
      '': 'log',
      'in': 'log',
      'out': 'log',
      }
  _QUICK_TABLE = {
      'accept': 'quick',
      'deny': 'quick',
      'reject': 'quick',
      'next': '',
      }
  _DIRECTION_TABLE = {
      '': '',
      'in': 'in',
      'out': 'out',
      }
  _TCP_FLAGS_TABLE = {
      'syn': 'S',
      'ack': 'A',
      'fin': 'F',
      'rst': 'R',
      'urg': 'U',
      'psh': 'P',
      'all': 'SAFRUP',
      'none': 'NONE',
      }
  _PROTO_TABLE = {
      'icmpv6': 'ipv6-icmp',
      }
  _UNSUPPORTED_PROTOS = ['hopopt']

  def __init__(self, term, filter_name, stateful=True, af='inet', direction=''):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in packetfilter.
      filter_name: The name of the filter chan to attach the term to.
      stateful: Whether to keep firewall state for the term.
      af: Which address family ('inet' or 'inet6') to apply the term to.
      direction: What direction the term applies to ('in', 'out' or both).

    Raises:
      aclgenerator.UnsupportedFilterError: Filter is not supported.
    """
    super(Term, self).__init__(term)
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.options = []
    self.default_action = 'deny'
    self.af = af
    self.stateful = stateful
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

    ret_str = []
    self._SetDefaultAction()

    # Create a new term
    ret_str.append('\n# term %s' % self.term.name)

    comments = aclgenerator.WrapWords(self.term.comment, 80)
    # append comments to output
    if comments and comments[0]:
      for line in comments:
        ret_str.append('# %s' % str(line))

    if str(self.term.action[0]) not in self._ACTION_TABLE:
      raise aclgenerator.UnsupportedFilterError('%s %s %s %s' % (
          '\n', self.term.name, self.term.action[0],
          'action not currently supported.'))

    if self.direction and str(self.direction) not in self._DIRECTION_TABLE:
      raise aclgenerator.UnsupportedFilterError('%s %s %s %s' % (
          '\n', self.term.name, self.term.direction,
          'direction not currently supported.'))
    # protocol
    if self.term.protocol:
      protocol = self.term.protocol
    else:
      protocol = []

    # source address
    term_saddrs = self._CheckAddressAf(self.term.source_address)
    if not term_saddrs:
      logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                   direction='source',
                                                   af=self.af))
      return ''
    term_saddr = self._GenerateAddrStatement(
        term_saddrs, self.term.source_address_exclude)

    # destination address
    term_daddrs = self._CheckAddressAf(self.term.destination_address)
    if not term_daddrs:
      logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                   direction='destination',
                                                   af=self.af))
      return ''
    term_daddr = self._GenerateAddrStatement(
        term_daddrs, self.term.destination_address_exclude)

    # ports
    source_port = []
    destination_port = []
    if self.term.source_port:
      source_port = self._GeneratePortStatement(self.term.source_port)
    if self.term.destination_port:
      destination_port = self._GeneratePortStatement(self.term.destination_port)

    # icmp-type
    icmp_types = ['']
    if self.term.icmp_type:
      if self.af != 'mixed':
        af = self.af
      elif protocol == ['icmp']:
        af = 'inet'
      elif protocol == ['icmpv6']:
        af = 'inet6'
      else:
        raise aclgenerator.UnsupportedFilterError('%s %s %s' % (
            '\n', self.term.name,
            'icmp protocol is not defined or not supported.'))
      icmp_types = self.NormalizeIcmpTypes(
          self.term.icmp_type, protocol, af)

    # options
    tcp_flags_set = []
    tcp_flags_check = []
    for next_opt in [str(x) for x in self.term.option]:
      for next_flag in self._TCP_FLAGS_TABLE:
        if next_opt.find(next_flag) == 0:
          if protocol != ['tcp']:
            raise aclgenerator.UnsupportedFilterError('%s %s %s' % (
                '\n', self.term.name,
                'tcp flags may only be specified with tcp protocol.'))
          tcp_flags_set.append(self._TCP_FLAGS_TABLE.get(next_flag))
          tcp_flags_check.append(self._TCP_FLAGS_TABLE.get(next_flag))

    # If tcp-established is set, override any of the flags above with the
    # S/SA flags.  Issue an error if flags are specified with 'established'.
    for opt in [str(x) for x in self.term.option]:
      if opt == 'established' or opt == 'tcp-established':
        if tcp_flags_set or tcp_flags_check:
          raise aclgenerator.UnsupportedFilterError('%s %s %s' % (
              '\n', self.term.name,
              'tcp flags may not be specified with tcp-established.'))
        # We need to set 'flags A/A' for established regardless of whether or
        # not we're stateful:
        # - if we stateful, the default is 'flags S/SA' which prevent writing
        # rules for reply packets.
        # - if we're stateless, this is the only way to do it.
        if not protocol or 'tcp' in protocol:
          tcp_flags_set.append(self._TCP_FLAGS_TABLE.get('ack'))
          tcp_flags_check.append(self._TCP_FLAGS_TABLE.get('ack'))

    # The default behavior of pf is 'keep state flags S/SA'.  If we're not
    # stateless, and if flags have not been specified explicitly via options,
    # append that here.  Note that pf allows appending flags for udp and icmp;
    # they are just ignored, as long as TCP is in the proto.  This lets you
    # doing things like 'proto { tcp udp icmp } flags S/SA' and have the flags
    # only applied to the tcp bits that match.  However, the policy description
    # language prohibits setting flags on non-TCP, since it doesn't make sense
    # on all platforms.
    if ((not protocol or protocol == ['tcp']) and self.stateful
        and not tcp_flags_set and not tcp_flags_check):
      tcp_flags_set.append(self._TCP_FLAGS_TABLE.get('syn'))
      tcp_flags_check.append(self._TCP_FLAGS_TABLE.get('syn'))
      tcp_flags_check.append(self._TCP_FLAGS_TABLE.get('ack'))

    ret_str.extend(self._FormatPart(
        self.term.action[0],
        self.direction,
        self.term.logging,
        self.af,
        protocol,
        term_saddr,
        source_port,
        term_daddr,
        destination_port,
        tcp_flags_set,
        tcp_flags_check,
        icmp_types,
        self.options,
        self.stateful,))

    return '\n'.join(str(v) for v in ret_str if v is not '')

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

  def _FormatPart(self, action, direction, log, af, proto, src_addr, src_port,
                  dst_addr, dst_port, tcp_flags_set, tcp_flags_check,
                  icmp_types, options, stateful):
    """Format the string which will become a single PF entry."""
    line = ['%s' % self._ACTION_TABLE.get(action)]

    if direction:
      line.append(direction)

    quick = self._QUICK_TABLE.get(action)
    if quick:
      line.append('%s' % quick)

    if log:
      logaction = self._LOG_TABLE.get(direction)
      if logaction:
        line.append(logaction)
      else:
        line.append('log')

    if af != 'mixed':
      line.append(af)

    if proto:
      line.append(self._GenerateProtoStatement(proto))

    line.append('from %s' % src_addr)
    if src_port:
      line.append('port %s' % src_port)

    line.append('to %s' % dst_addr)
    if dst_port:
      line.append('port %s' % dst_port)

    if tcp_flags_set and tcp_flags_check:
      line.append('flags')
      line.append('%s/%s' % (''.join(tcp_flags_set), ''.join(tcp_flags_check)))

    if 'icmp' in proto and icmp_types:
      type_strs = [str(icmp_type) for icmp_type in icmp_types]
      type_strs = ', '.join(type_strs)
      if type_strs:
        line.append('icmp-type { %s }' % type_strs)

    if options:
      line.extend(options)

    if not stateful:
      line.append('no state')
    elif action in ['accept', 'next']:
      line.append('keep state')

    return [' '.join(line)]

  def _GenerateProtoStatement(self, protocols):
    proto = ''
    if protocols:
      protocols = copy.deepcopy(protocols)
      for i, proto in enumerate(protocols):
        if proto in self._UNSUPPORTED_PROTOS:
          raise UnsupportedProtoError
        try:
          protocols[i] = self._PROTO_TABLE[proto]
        except KeyError:
          pass
      proto = 'proto { %s }' % ' '.join(protocols)
    return proto

  def _GenerateAddrStatement(self, addrs, exclude_addrs):
    addresses = set()
    if addrs != ['any']:
      parent_token_set = set()
      for addr in addrs:
        parent_token_set.add(addr.parent_token)
      for token in parent_token_set:
        addresses.add('<%s>' % token[:31])
    else:
      addresses.add('any')
    if exclude_addrs != ['any']:
      parent_token_set = set()
      for addr in exclude_addrs:
        parent_token_set.add(addr.parent_token)
      for token in parent_token_set:
        addresses.add('!<%s>' % token[:31])
    return '{ %s }' % ', '.join(sorted(addresses))

  def _GeneratePortStatement(self, ports):
    port_list = []
    for port_tuple in ports:
      if port_tuple[0] == port_tuple[1]:
        port_list.append(str(port_tuple[0]))
      else:
        port_list.append('%s:%s' % (port_tuple[0], port_tuple[1]))
    return '{ %s }' % (
        ' '.join(list(collections.OrderedDict.fromkeys(port_list))))

  def _SetDefaultAction(self):
    """If term does not specify action, use filter default action."""
    if not self.term.action:
      self.term.action[0].value = self.default_action


class PacketFilter(aclgenerator.ACLGenerator):
  """Generates filters and terms from provided policy object."""

  _DEF_MAX_LENGTH = 31
  _PLATFORM = 'packetfilter'
  _DEFAULT_PROTOCOL = 'all'
  SUFFIX = '.pf'
  _TERM = Term

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(
        PacketFilter, self)._BuildTokens()

    supported_tokens |= {'logging'}
    supported_sub_tokens.update({
        'action': {'accept', 'deny', 'reject', 'next'},
        'option': {
            'established',
            'tcp-established',
            'syn',
            'ack',
            'fin',
            'rst',
            'urg',
            'psh',
            'all'},
    })

    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.pf_policies = []
    self.address_book = {}
    self.def_short_to_long = {}
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    good_afs = ['inet', 'inet6', 'mixed']
    good_options = ['in', 'out', 'nostate']
    all_protocols_stateful = True

    for header, terms in pol.filters:
      filter_type = None
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)[1:]
      filter_name = header.FilterName(self._PLATFORM)
      direction = ''

      # ensure all options after the filter name are expected
      for opt in filter_options:
        if opt not in good_afs + good_options:
          raise aclgenerator.UnsupportedTargetOption('%s %s %s %s' % (
              '\nUnsupported option found in', self._PLATFORM,
              'target definition:', opt))

      # pf will automatically add 'keep state flags S/SA' to all TCP connections
      # by default.
      if 'nostate' in filter_options:
        all_protocols_stateful = False

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
        filter_type = 'inet'

      # add the terms
      new_terms = []
      term_names = set()

      for term in terms:
        term.name = self.FixTermLength(term.name)
        if term.name in term_names:
          raise DuplicateTermError(
              'You have a duplicate term: %s' % term.name)
        term_names.add(term.name)

        for source_addr in term.source_address:
          src_token = source_addr.parent_token[:self._DEF_MAX_LENGTH]

          if (src_token in self.def_short_to_long and
              self.def_short_to_long[src_token] != source_addr.parent_token):
            raise DuplicateShortenedTableName(
                'There is a shortened name conflict between names %s and %s '
                '(different named objects would conflict when shortened to %s)'
                % (self.def_short_to_long[src_token],
                   source_addr.parent_token,
                   src_token))
          else:
            self.def_short_to_long[src_token] = source_addr.parent_token

          if src_token not in self.address_book:
            self.address_book[src_token] = set([source_addr])
          else:
            self.address_book[src_token].add(source_addr)

        for dest_addr in term.destination_address:
          dst_token = dest_addr.parent_token[:self._DEF_MAX_LENGTH]

          if (dst_token in self.def_short_to_long and
              self.def_short_to_long[dst_token] != dest_addr.parent_token):
            raise DuplicateShortenedTableName(
                'There is a shortened name conflict between names %s and %s '
                '(different named objects would conflict when shortened to %s)'
                %(self.def_short_to_long[dst_token],
                  dest_addr.parent_token,
                  dst_token))
          else:
            self.def_short_to_long[dst_token] = dest_addr.parent_token

          if dst_token not in self.address_book:
            self.address_book[dst_token] = set([dest_addr])
          else:
            self.address_book[dst_token].add(dest_addr)

        if not term:
          continue

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warn('WARNING: Term %s in policy %s is expired and '
                         'will not be rendered.', term.name, filter_name)
            continue

        new_terms.append(self._TERM(term, filter_name, all_protocols_stateful,
                                    filter_type, direction))

      self.pf_policies.append((header, filter_name, filter_type, new_terms))

  def __str__(self):
    """Render the output of the PF policy into config."""
    target = []
    pretty_platform = '%s%s' % (self._PLATFORM[0].upper(), self._PLATFORM[1:])
    # Create address table.
    for name in sorted(self.address_book):
      entries = ',\\\n'.join(str(x) for x in
                             sorted(self.address_book[name], key=int))
      target.append('table <%s> {%s}' % (name, entries))
    # pylint: disable=unused-variable
    for (header, filter_name, filter_type, terms) in self.pf_policies:
      # Add comments for this filter
      target.append('# %s %s Policy' % (pretty_platform,
                                        header.FilterName(self._PLATFORM)))

      # reformat long text comments, if needed
      comments = aclgenerator.WrapWords(header.comment, 70)
      if comments and comments[0]:
        for line in comments:
          target.append('# %s' % line)
        target.append('#')
      # add the p4 tags
      target.extend(aclgenerator.AddRepositoryTags('# '))
      target.append('# ' + filter_type)

      # add the terms
      for term in terms:
        term_str = str(term)
        if term_str:
          target.append(term_str)
      target.append('')

    return '\n'.join(target)
