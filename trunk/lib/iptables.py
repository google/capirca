#!/usr/bin/python
#
# Copyright 2009 Google Inc.
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


"""Iptables generator."""

__author__ = 'watson@google.com (Tony Watson)'

import nacaddr
import policy


class Term(object):
  """Generate Iptables policy terms."""

  def __init__(self, term, filter_name, filter_action, af = 'inet'):
    """
    Setup a new term.

    Args:
      term: A policy.Term object to represent in iptables.
      filter_name: The name of the filter chan to attach the term to.
      filter_action: The default action of the filter.
      af: Which address family ('inet' or 'inet6') to apply the term to.
      truncate: Whether to truncate names to meet iptables limits.
    """
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.default_action = filter_action
    self.options = []
    self.af = af
    # Iptables enforces 30 char limit, but weirdness happens after 28 or 29
    if len(self.term.name) > 24:
      raise TermNameTooLong(
          'Term %s is too long, limit is 24 characters.' %  self.term.name)
    
    self._ACTION_TABLE = {
      'accept': '-j ACCEPT',
      'deny': '-j DROP',
      'reject': '-j REJECT --reject-with icmp-host-prohibited',
      'reject-with-tcp-rst': '-j REJECT --reject-with tcp-reset',
      'next': '-j RETURN'
      }
    self._PROTO_TABLE = {
      'icmp': '-p icmp',
      'tcp': '-p tcp',
      'udp': '-p udp',
      'all': '-p all',
      'esp': '-p esp',
      'ah': '-p ah',
      'gre': '-p gre',
      }
    self._FLAGS_TABLE = {
      'syn': 'SYN',
      'ack': 'ACK',
      'fin': 'FIN',
      'rst': 'RST',
      'urg': 'URG',
      'psh': 'PSH',
      'all': 'ALL',
      'none': 'NONE',
      }
    self._all_ips = nacaddr.IPv4('0.0.0.0/0')
    if af == 'inet6':
      self._all_ips = nacaddr.IPv6('::/0')
      self._ACTION_TABLE['reject'] = '-j REJECT --reject-with adm-prohibited'
      self._PROTO_TABLE['icmp'] = '-p icmpv6'

  def __str__(self):
    ret_str = []
    # Term verbatim output - this will skip over most normal term
    # creation code by returning early. Warnings provided in policy.py
    if self.term.verbatim:
      for next in self.term.verbatim:
        if next.value[0] == 'iptables':
          ret_str.append(str(next.value[1]))
      return '\n'.join(ret_str)

    # Create a new term
    ret_str.append('-N %s' % self.term.name)  # New term
    comments = WrapWords(self.term.comment, 40)
    # append comments to output
    if comments and comments[0] != '':
      for line in comments:
        ret_str.append('-A %s -m comment --comment "%s"' %
                       (self.term.name, str(line)))  # Term comments

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action

    # protocol
    if not self.term.protocol:
      term_protocol = [policy.VarType(policy.VarType.PROTOCOL, 'all')]
    else:
      term_protocol = self.term.protocol

    # source address
    term_saddr = self.term.source_address
    if not term_saddr:
      term_saddr = [self._all_ips]
    if self.term.source_address_exclude:
      term_saddr = nacaddr.ExcludeAddrs(
          term_saddr, self.term.source_address_exclude)

    # destination address
    term_daddr = self.term.destination_address
    if not term_daddr:
      term_daddr = [self._all_ips]
    if self.term.destination_address_exclude:
      term_daddr = nacaddr.ExcludeAddrs(
          term_daddr,
          self.term.destination_address_exclude)

    # ports
    # because we are looping through ports, we must have something in each
    # so we define as null if empty and later replace with ''.
    if not self.term.source_port:
      term_source_port = ['NULL']
    else:
      term_source_port = self.term.source_port
    if not self.term.destination_port:
      term_destination_port = ['NULL']
    else:
      term_destination_port = self.term.destination_port

    # options
    tcp_flags = []
    for next in [str(x) for x in self.term.option]:
      if (next.find('established') == 0 and term_protocol == ['tcp']
          and 'ESTABLISHED' not in [x.strip() for x in self.options]):
        self.options.append('-m state --state ESTABLISHED,RELATED')
      if next.find('tcp-established') == 0:
        if term_protocol == ['tcp']:
          # only allow tcp-established if proto is explicitly 'tcp' only
          self.options.append('-m state --state ESTABLISHED,RELATED')
        else:
          raise TcpEstablishedError(
              'option tcp-established can only be applied for proto tcp.')
      # Iterate through flags table, and create list of tcp-flags to append
      for next_flag in self._FLAGS_TABLE:
        if next.find(next_flag) == 0:
          tcp_flags.append(self._FLAGS_TABLE.get(next_flag))

    for saddr in term_saddr:
      for daddr in term_daddr:
        for sport in term_source_port:
          if sport == 'NULL': sport = ''
          for dport in term_destination_port:
            if dport == 'NULL': dport = ''
            for protocol in term_protocol:
              ret_str.append(self._FormatPart(
                  self.af,
                  str(protocol),
                  saddr,
                  sport,
                  daddr,
                  dport,
                  self.options,
                  tcp_flags,
                  self._ACTION_TABLE.get(str(self.term.action[0]))
                  ))
    # Add this term to the filters jump table
    ret_str.append('-A %s -j %s' % (self.filter, self.term.name))
    return '\n'.join(str(v) for v in ret_str if v is not '')
  
  def _FormatPart(self, af, protocol, saddr, sport, daddr, dport, options,
                  tcp_flags, action):
    """Compose one iteration of the term parts into a string.

    Args:
      af: Address family, inet|inet6
      protocol: The network protocol
      saddr: Source IP address
      sport: Source port number
      daddr: Destination IP address
      dport: Destination port number
      options: Optional arguments to append to our rule
      tcp_flags: Which tcp_flag arguments, if any, should be appended
      action: What should happen if this rule matches

    Returns;
      rval:  A single iptables argument line
    """
    src = ''
    dst = ''
    # Check that AF matches and is what we want
    if saddr.version != daddr.version:
      return ''
    if (af == 'inet') and (saddr.version != 4):
      return ''
    if (af == 'inet6') and (saddr.version != 6):
      return ''
    filter_top = '-A ' + self.term.name
    # fix addresses
    if saddr == self._all_ips:
      src = ''
    else:
      src = '-s ' + saddr.ip_ext + '/' + str(saddr.prefixlen)

    if daddr == self._all_ips:
      dst = ''
    else:
      dst = '-d ' + daddr.ip_ext + '/' + str(daddr.prefixlen)

    # fix ports
    if sport:
      if sport[0] != sport[1]:
        sport = '--sport %d:%d' % (sport[0], sport[1])
      elif sport:
        sport = '--sport %d' % (sport[0])

    if dport:
      if dport[0] != dport[1]:
        dport = '--dport %d:%d' % (dport[0], dport[1])
      elif dport:
        dport = '--dport %d' % (dport[0])

    proto = self._PROTO_TABLE.get(str(protocol))

    if not options:
      option = ['']
    if not tcp_flags:
      flags = ''
    else:
      flags = '--tcp-flags ' + ','.join(tcp_flags) + ' ' + ','.join(tcp_flags)

    rval = filter_top
    tmp_ops = ' '.join(options)
    for value in proto, flags, sport, dport, src, dst, tmp_ops, action:
      if value:
        rval = rval + ' ' + str(value)
    return rval


class Iptables(object):
  """Generates filters and terms from provided policy object."""

  suffix = '.ipt'

  def __init__(self, pol):
    for header in pol.headers:
      if 'iptables' not in header.platforms:
        raise NoIptablesPolicyError('no iptables policy found in %s' % (
            header.target))

    self.policy = pol

  def __str__(self):
    target = []
    default_action = ''
    good_default_actions = ['', 'ACCEPT', 'DROP']
    good_filters = ['INPUT', 'OUTPUT', 'FORWARD']
    good_afs = ['inet', 'inet6']

    for header, terms in self.policy.filters:
      filter_name = header.FilterName('iptables')
      if filter_name not in good_filters:
        raise UnsupportedFilter(
            'Only INPUT, OUTPUT, and FORWARD filters allowed; %s used.'
            % filter_name)
      # Check for matching af
      filter_options = header.FilterOptions('iptables')
      filter_type = 'inet'
      if (len(filter_options) > 0) and (filter_options[-1] in good_afs):
        filter_type = filter_options[-1]
      # Add comments for this filter
      target.append('# Speedway Iptables %s Policy' %
                    header.FilterName('iptables'))
      comments = WrapWords(header.comment, 70)
      if comments and comments[0] != '':
        for line in comments:
          target.append('# %s' % line)
      target.append('#')
      # add the p4 tags
      p4_id = '$I' + 'd:$'
      p4_date = '$Da' + 'te:$'
      target.append('# %s' % p4_id)
      target.append('# %s' % p4_date)
      target.append('# ' + filter_type)

      if filter_name == 'FORWARD':
        default_action = 'DROP'
      # does this policy override the default filter actions?
      for next in header.target:
        if next.platform == 'iptables':
          if (len(next.options) > 1) and (next.options[1] not in good_afs):
            default_action = next.options[1]
      if default_action not in good_default_actions:
        raise UnsupportedDefaultAction(
            'Only ACCEPT or DROP default filter action allowed; %s used.'
            % default_action)
      # setup the default filter states.
      # if default action policy not specified, do nothing.
      if default_action:
        target.append('-P %s %s' % (filter_name, default_action))

      # add the terms
      for term in terms:
        target.append(str(Term(term, filter_name, default_action, filter_type)))
      target.append('\n')
    return '\n'.join(target)


def WrapWords(textlist, size):
  """Convert a list of strings into a new list of specified width.

  Args:
    textlist: a list of text strings
    size: width of reformated strings
  Returns:
    text_new: converted list
  """
  text_new = []
  for line in textlist:
    if len(line) <= size:
      text_new.append(line)
    else:  # reformat and split lines longer than $size
      words = line.replace('\n', ' \n ').split(' ')
      # ^ make sure newlines split out as 'words' ^
      line = ''
      current_size = 0
      for nextword in words:
        if nextword == '\n':
          text_new.append(line)
          line = ''
          current_size = 0
        else:
          current_size += len(nextword)
          if current_size <= size:
            line += '%s ' % nextword
          else:
            text_new.append(line[:-1])
            current_size = len(nextword)
            line = '%s ' % nextword
      text_new.append(line[:-1])

  return text_new


# generic error class
class Error(Exception):
  """Base error class."""


class TermNameTooLong(Error):
  """Term name is too long."""


class UnsupportedFilter(Error):
  """Raised when we see an inappropriate filter."""


class NoIptablesPolicyError(Error):
  """Raised when a policy is received that doesn't support iptables."""


class TcpEstablishedError(Error):
  """Raised when a term has tcp-established option but not proto tcp only."""


class UnsupportedDefaultAction(Error):
  """Raised when a filter has an impermissible default action specified."""

