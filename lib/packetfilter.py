#!/usr/bin/python
#
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

__author__ = 'msu@google.com (Martin Suess)'

import aclgenerator
import datetime
import logging
import nacaddr
import re


class Error(Exception):
  """Base error class."""


class UnsupportedFilterError(Error):
  """Raised when we see an inappropriate filter."""


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
      }
  _TCP_FLAGS_TABLE = {
      'syn': 'S',
      'ack': 'A',
      'fin': 'F',
      'rst': 'R',
      'urg': 'U',
      'psh': 'P',
      'all': 'ALL',
      'none': 'NONE',
      }

  def __init__(self, term, filter_name, af='inet'):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in packetfilter.
      filter_name: The name of the filter chan to attach the term to.
      af: Which address family ('inet' or 'inet6') to apply the term to.

    Raises:
      UnsupportedFilterError: Filter is not supported.
    """
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.options = []
    self.af = af

  def __str__(self):
    """Render config output from this term object."""
    ret_str = []

    # Create a new term
    ret_str.append('\n# term %s' % self.term.name)
    # append comments to output
    for line in self.term.comment:
      if not line:
        continue
      ret_str.append('# %s' % str(line))

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action

    # protocol
    if self.term.protocol:
      protocol = self.term.protocol
    else:
      protocol = []
    if self.term.protocol_except:
      raise UnsupportedFilterError('%s %s %s' % (
          '\n', self.term.name,
          'protocol_except logic not currently supported.'))

    # source address
    term_saddrs = self._CheckAddressAf(self.term.source_address)
    if not term_saddrs: return ''
    term_saddr = self._GenerateAddrStatement(term_saddrs,
        self.term.source_address_exclude)

    # destination address
    term_daddrs = self._CheckAddressAf(self.term.destination_address)
    if not term_daddrs: return ''
    term_daddr = self._GenerateAddrStatement(term_daddrs,
        self.term.destination_address_exclude)

    # ports
    source_port = []
    destination_port = []
    if self.term.source_port:
      source_port = self._GeneratePortStatement(self.term.source_port)
    if self.term.destination_port:
      destination_port = self._GeneratePortStatement(self.term.destination_port)

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      if self.af != 'mixed':
        af = self.af
      elif protocol == ['icmp']:
        af = 'inet'
      elif protocol == ['icmp6']:
        af = 'inet6'
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type, protocol,
                                           af, self.term.name)

    # options
    opts = [str(x) for x in self.term.option]
    tcp_flags = []
    for next_opt in opts:
      # Iterate through flags table, and create list of tcp-flags to append
      for next_flag in self._TCP_FLAGS_TABLE:
        if next_opt.find(next_flag) == 0:
          tcp_flags.append(self._TCP_FLAGS_TABLE.get(next_flag))

    ret_str.extend(self._FormatPart(
        self._ACTION_TABLE.get(str(self.term.action[0])),
        self.term.logging,
        self.af,
        protocol,
        term_saddr,
        source_port,
        term_daddr,
        destination_port,
        tcp_flags,
        icmp_types,
        self.options,
        ))

    return '\n'.join(str(v) for v in ret_str if v is not '')

  def _CheckAddressAf(self, addrs):
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

  def _FormatPart(self, action, logging, af, proto, src_addr, src_port,
                  dst_addr, dst_port, tcp_flags, icmp_types, options):
    line = ['%s' % action]
    if logging and 'true' in [str(l) for l in logging]:
      line.append('log')

    line.append('quick')
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

    if 'tcp' in proto and tcp_flags:
      line.append('flags')
      line.append('/'.join(tcp_flags))

    if 'icmp' in proto and icmp_types:
      type_strs = [str(icmp_type) for icmp_type in icmp_types]
      line.append('icmp-types { %s }' % ', '.join(type_strs))

    if options:
      line.extend(options)

    return [' '.join(line)]

  def _GenerateProtoStatement(self, protocols):
    proto = ''
    if protocols:
      proto = 'proto { %s }' % ' '.join(protocols)
    return proto

  def _GenerateAddrStatement(self, addrs, exclude_addrs):
    addresses = [str(addr) for addr in addrs]
    for exlude_addr in exclude_addrs:
      addresses.append('!%s' % str(exclude_addr))
    return '{ %s }' % ', '.join(addresses)

  def _GeneratePortStatement(self, ports):
    port_list = []
    for port_tuple in ports:
      for port in port_tuple:
        port_list.append(str(port))
    return '{ %s }' % ' '.join(list(set(port_list)))


class PacketFilter(aclgenerator.ACLGenerator):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'packetfilter'
  _DEFAULT_PROTOCOL = 'all'
  _SUFFIX = '.pf'
  _TERM = Term
  _OPTIONAL_SUPPORTED_KEYWORDS = set(['expiration',
                                      'logging',
                                     ])

  def _TranslatePolicy(self, pol):
    self.pf_policies = []
    current_date = datetime.date.today()

    default_action = None
    good_afs = ['inet', 'inet6', 'mixed']
    good_options = []
    all_protocols_stateful = True
    filter_type = None

    for header, terms in pol.filters:
      if not self._PLATFORM in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)[1:]
      filter_name = header.FilterName(self._PLATFORM)

      # ensure all options after the filter name are expected
      for opt in filter_options:
        if opt not in good_afs + good_options:
          raise UnsupportedTargetOption('%s %s %s %s' % (
              '\nUnsupported option found in', self._PLATFORM,
              'target definition:', opt))

      # Check for matching af
      for address_family in good_afs:
        if address_family in filter_options:
          # should not specify more than one AF in options
          if filter_type is not None:
            raise UnsupportedFilterError('%s %s %s %s' % (
                '\nMay only specify one of', good_afs, 'in filter options:',
                filter_options))
          filter_type = address_family
      if filter_type is None:
        filter_type = 'mixed'

      # add the terms
      new_terms = []
      term_names = set()
      for term in terms:
        if term.name in term_names:
          raise aclgenerator.DuplicateTermError(
              'You have a duplicate term: %s' % term.name)
        term_names.add(term.name)

        if not term:
          continue

        if term.expiration and term.expiration <= current_date:
          logging.warn('WARNING: Term %s in policy %s is expired and will '
                       'not be rendered.', term.name, filter_name)
          continue

        new_terms.append(self._TERM(term, filter_name, filter_type))

      self.pf_policies.append((header, filter_name, filter_type, new_terms))

  def __str__(self):
    """Render the output of the PF policy into config."""
    target = []
    pretty_platform = '%s%s' % (self._PLATFORM[0].upper(), self._PLATFORM[1:])

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
      target.append('\n')

    return '\n'.join(target)
