# Copyright 2011 Capirca Project Authors All Rights Reserved.
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


"""Cisco ASA renderer."""

import datetime
import ipaddress
import logging
import re
from typing import cast

from capirca.lib import aclgenerator
from capirca.lib import cisco
from capirca.lib import nacaddr
from capirca.lib import summarizer


_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
    }


# generic error class
class Error(Exception):
  """Generic error class."""
  pass


class UnsupportedCiscoAccessListError(Error):
  """Raised when we're give a non named access list."""
  pass


class StandardAclTermError(Error):
  """Raised when there is a problem in a standard access list."""
  pass


class NoCiscoPolicyError(Error):
  """Raised when a policy is errantly passed to this module for rendering."""
  pass


class Term(cisco.Term):
  """A single ACL Term."""

  def __init__(self, term, filter_name, af=4, enable_dsmo=False):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    assert af in (4, 6)
    self.af = af
    self.enable_dsmo = enable_dsmo

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'ciscoasa' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'ciscoasa' in self.term.platform_exclude:
        return ''

    ret_str = ['\n']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      ret_str.append('remark Term %s' % self.term.name)
      ret_str.append('remark not rendered due to protocol/AF mismatch.')
      return '\n'.join(ret_str)

    ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                 self.term.name))
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                     str(line)[:100]))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for line in self.term.verbatim:
        if line[0] == 'ciscoasa':
          ret_str.append(str(line[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      protocol = ['ip']
    else:
      # fix the protocol
      protocol = self.term.protocol

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', self.af)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.af)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
      if len(source_address) > 1 and self.enable_dsmo:
        source_address = summarizer.Summarize(source_address)
    else:
      # source address not set
      source_address = ['any']

    # destination address
    if self.term.destination_address:
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', self.af)
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', self.af)
      if destination_address_exclude:
        destination_address = nacaddr.ExcludeAddrs(
            destination_address,
            destination_address_exclude)
      if len(destination_address) > 1 and self.enable_dsmo:
        destination_address = summarizer.Summarize(destination_address)
    else:
      # destination address not set
      destination_address = ['any']

    # options
    extra_options = []
    for opt in [str(x) for x in self.term.option]:
      if opt.find('tcp-established') == 0 and 6 in protocol:
        extra_options.append('established')
      elif opt.find('established') == 0 and 6 in protocol:
        # only needed for TCP, for other protocols policy.py handles high-ports
        extra_options.append('established')
    self.options.extend(extra_options)

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    if self.term.logging:
      self.options.append('log')
      if 'disable' in [x.value for x in self.term.logging]:
        self.options.append('disable')

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol, self.af)

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              for icmp_type in icmp_types:
                # only output address family appropriate IP addresses
                do_output = False
                if self.af == 4:
                  if (((isinstance(saddr, nacaddr.IPv4)) or
                       (saddr == 'any')) and
                      ((isinstance(daddr, nacaddr.IPv4)) or (daddr == 'any'))):
                    do_output = True
                  elif isinstance(saddr, summarizer.DSMNet) or isinstance(daddr, summarizer.DSMNet):
                    do_output = True
                if self.af == 6:
                  if (((isinstance(saddr, nacaddr.IPv6)) or
                       (saddr == 'any')) and
                      ((isinstance(daddr, nacaddr.IPv6)) or (daddr == 'any'))):
                    do_output = True
                if do_output:
                  ret_str.extend(self._TermletToStr(
                      self.filter_name,
                      _ACTION_TABLE.get(str(self.term.action[0])),
                      proto,
                      saddr,
                      sport,
                      daddr,
                      dport,
                      icmp_type,
                      self.options))

    return '\n'.join(ret_str)

  def _TermletToStr(self, filter_name, action, proto, saddr, sport, daddr,
                    dport, icmp_type, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      filter_name: name of the filter
      action: str, action
      proto: str, protocl
      saddr: str or ipaddress, source address
      sport: str list or none, the source port
      daddr: str or ipaddress, the destination address
      dport: str list or none, the destination port
      icmp_type: icmp-type numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.
    """
    # inet4
    if isinstance(saddr, nacaddr.IPv4) or isinstance(saddr,
                                                     ipaddress.IPv4Network):
      saddr = cast(self.IPV4_ADDRESS, saddr)
      if saddr.num_addresses > 1:
        saddr = '%s %s' % (saddr.network_address, saddr.netmask)
      else:
        saddr = 'host %s' % (saddr.network_address)
    if isinstance(daddr, nacaddr.IPv4) or isinstance(daddr,
                                                     ipaddress.IPv4Network):
      daddr = cast(self.IPV4_ADDRESS, daddr)
      if daddr.num_addresses > 1:
        daddr = '%s %s' % (daddr.network_address, daddr.netmask)
      else:
        daddr = 'host %s' % (daddr.network_address)
    # inet6
    if isinstance(saddr, nacaddr.IPv6) or isinstance(saddr,
                                                     ipaddress.IPv6Network):
      saddr = cast(self.IPV6_ADDRESS, saddr)
      if saddr.num_addresses > 1:
        saddr = '%s/%s' % (saddr.network_address, saddr.prefixlen)
      else:
        saddr = 'host %s' % (saddr.network_address)
    if isinstance(daddr, nacaddr.IPv6) or isinstance(daddr,
                                                     ipaddress.IPv6Network):
      daddr = cast(self.IPV6_ADDRESS, daddr)
      if daddr.num_addresses > 1:
        daddr = '%s/%s' % (daddr.network_address, daddr.prefixlen)
      else:
        daddr = 'host %s' % (daddr.network_address)

    if isinstance(saddr, summarizer.DSMNet):
      saddr = '%s %s' % summarizer.ToDottedQuad(saddr, negate=False)
      if saddr.endswith('255.255.255.255'):
        saddr = f'host {saddr.split()[0]}'

    if isinstance(daddr, summarizer.DSMNet):
      daddr = '%s %s' % summarizer.ToDottedQuad(daddr, negate=False)
      if daddr.endswith('255.255.255.255'):
        daddr = f'host {daddr.split()[0]}'

    # fix ports
    if not sport:
      sport = ''
    elif sport[0] != sport[1]:
      sport = ' range %s %s' % (cisco.PortMap.GetProtocol(sport[0], proto),
                                cisco.PortMap.GetProtocol(sport[1], proto))
    else:
      sport = ' eq %s' % (cisco.PortMap.GetProtocol(sport[0], proto))

    if not dport:
      dport = ''
    elif dport[0] != dport[1]:
      dport = ' range %s %s' % (cisco.PortMap.GetProtocol(dport[0], proto),
                                cisco.PortMap.GetProtocol(dport[1], proto))
    else:
      dport = ' eq %s' % (cisco.PortMap.GetProtocol(dport[0], proto))

    if not option:
      option = ['']

    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if proto == 'udp' and 'established' in sane_options:
      sane_options.remove('established')

    ret_lines = []

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(cisco.PortMap.GetProtocol(icmp_type, 'icmp'))

    ret_lines.append('access-list %s extended  %s %s %s %s %s %s %s %s' %
                     (filter_name, action, proto, saddr,
                      sport, daddr, dport,
                      icmp_type,
                      ' '.join(sane_options)
                     ))

    # remove any trailing spaces and replace multiple spaces with singles
    stripped_ret_lines = [re.sub(r'\s+', ' ', x).rstrip() for x in ret_lines]
    return stripped_ret_lines


class CiscoASA(aclgenerator.ACLGenerator):
  """A cisco ASA policy object."""

  _PLATFORM = 'ciscoasa'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.asa'

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'logging', 'owner'}

    supported_sub_tokens.update({'option': {'established', 'tcp-established'},
                                 # Warning, some of these are mapped
                                 # differently. See _ACTION_TABLE
                                 'action': {'accept', 'deny', 'reject', 'next',
                                            'reject-with-tcp-rst'}})
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.ciscoasa_policies = []
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in self.policy.filters:
      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      new_terms = []
      # now add the terms
      for term in terms:
        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue

        enable_dsmo = len(filter_options) > 1 and 'enable_dsmo' in filter_options[1:]
        new_terms.append(str(Term(term, filter_name, enable_dsmo=enable_dsmo)))

      self.ciscoasa_policies.append((header, filter_name, new_terms))

  def __str__(self):
    target = []

    for (header, filter_name, terms) in self.ciscoasa_policies:

      target.append('clear configure access-list %s' % filter_name)

      # add the p4 tags
      target.extend(aclgenerator.AddRepositoryTags('access-list %s remark '
                                                   % filter_name))

      # add a header comment if one exists
      for comment in header.comment:
        for line in comment.split('\n'):
          target.append('access-list %s remark %s' % (filter_name, line))

      # now add the terms
      for term in terms:
        target.append(str(term))

      # end for header, filter_name, filter_type...

    return '\n'.join(target)
