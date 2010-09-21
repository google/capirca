#!/usr/bin/python
#
# Copyright 2010 Google Inc.
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

import logging
import nacaddr
import re


class Term(object):
  """Generate Iptables policy terms."""

  # Validate that term does not contain any fields we do not
  # support.  This prevents us from thinking that our output is
  # correct in cases where we've omitted fields from term.
  _ALLOWED_KEYWORDS = set([
      # Basic operations
      'comment', 'action', 'verbatim', 'name',
      # IPtables only supports simple filtering (deliberately ignored)
      'loss_priority', 'precedence', 'policer', 'qos', 'routing_instance',
      'logging', 'counter', 'traffic_type',
      # Supported address limits
      'source_address', 'source_address_exclude',
      'destination_address', 'destination_address_exclude',
      # Other packet filtering
      'option', 'protocol', 'icmp_type',
      'source_port', 'destination_port', 'packet_length',
      # Unsupported address limits: may produce UnsupportedFilter exceptions
      # omitted with 'accept'/'next', error elsewise
      'source_prefix', 'destination_prefix',
      # Supported only for specific values (i.e. "1-6" for fragment_offset)
      'fragment_offset',
      # entirely unsupported - address and port imply something in
      # cisco which they do not imply in iptables. protocol_except
      # would require restructuring the generation loop to emit
      # returns + catch-all.
      'address', 'port', 'ether_type', 'protocol_except', 'translated',
      ])
  _ACTION_TABLE = {
      'accept': '-j ACCEPT',
      'deny': '-j DROP',
      'reject': '-j REJECT --reject-with icmp-host-prohibited',
      'reject-with-tcp-rst': '-j REJECT --reject-with tcp-reset',
      'next': '-j RETURN'
      }
  _PROTO_TABLE = {
      'icmp': '-p icmp',
      'tcp': '-p tcp',
      'udp': '-p udp',
      'all': '-p all',
      'esp': '-p esp',
      'ah': '-p ah',
      'gre': '-p gre',
      }
  _TCP_FLAGS_TABLE = {
      'syn': 'SYN',
      'ack': 'ACK',
      'fin': 'FIN',
      'rst': 'RST',
      'urg': 'URG',
      'psh': 'PSH',
      'all': 'ALL',
      'none': 'NONE',
      }
  _KNOWN_OPTIONS_MATCHERS = {
      # '! -f' also matches non-fragmented packets.
      'first-fragment': '-m u32 --u32 4&0x3FFF=0x2000',
      'initial': '--syn',
      'tcp-initial': '--syn',
      'sample': '',
      }
  # TODO(argent): automate the translation from policy-ese to
  # 'iptables -p icmp -h' names.
  _ICMP_POLICY_TO_NAMES = {'info-reply': '16',
                           'info-request': '15',
                           'mask-request': 'address-mask-request',
                           'mask-reply': 'address-mask-reply',
                           'router-solicit': 'router-solicitation',
                           'timestamp': 'timestamp-request',
                           'unreachable': 'destination-unreachable',
                          }

  def __init__(self, term, filter_name, trackstate, filter_action, af='inet',
               truncate=True):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in iptables.
      filter_name: The name of the filter chan to attach the term to.
      trackstate: Specifies if conntrack should be used for new connections
      filter_action: The default action of the filter.
      af: Which address family ('inet' or 'inet6') to apply the term to.
      truncate: Whether to truncate names to meet iptables limits.

    Raises:
      UnsupportedFilter: Filter is not supported.
    """
    self.trackstate = trackstate
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.default_action = filter_action
    self.options = []
    self.af = af
    for element in self.term.__dict__:
      if element not in self._ALLOWED_KEYWORDS:
        raise UnsupportedFilter('%s%s%s %s %s' % ('\n"', element, '" in term',
                                                  self.term.name,
                                                  'unsupported by iptables.'))
    # Iptables enforces 30 char limit, but weirdness happens after 28 or 29
    self.term_name = '%s_%s' % (
        self.filter[:1], self._CheckTermLength(self.term.name, 24, truncate))
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

    # We don't support these keywords for filtering, so unless users
    # put in a "verbatim:: iptables" statement, any output we emitted
    # would misleadingly suggest that we applied their filters.
    # Instead, we fail loudly.
    if self.term.ether_type:
      raise UnsupportedFilter('\n%s %s %s' % (
          'ether_type unsupported by iptables',
          '\nError in term', self.term.name))
    if self.term.address:
      raise UnsupportedFilter('\n%s %s %s' % (
          'address unsupported by iptables - specify source or dest',
          '\nError in term:', self.term.name))
    if self.term.port:
      raise UnsupportedFilter('\n%s %s %s' % (
          'port unsupported by iptables - specify source or dest',
          '\nError in term:', self.term.name))

    # Create a new term
    ret_str.append('-N %s' % self.term_name)  # New term

    # reformat long comments, if needed
    comments = WrapWords(self.term.comment, 40)
    # append comments to output
    if comments and comments[0]:
      for line in comments:
        if not line:
          continue  # iptables-restore does not like 0-length comments.
        # term comments
        ret_str.append('-A %s -m comment --comment "%s"' %
                       (self.term_name, str(line)))

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action

    # Unsupported configuration; in the case of 'accept' or 'next', we
    # skip the rule.  In other cases, we blow up (raise an exception)
    # to ensure that this is not considered valid configuration.
    if self.term.source_prefix or self.term.destination_prefix:
      if str(self.term.action[0]) not in set(['accept', 'next']):
        raise UnsupportedFilter('%s %s %s %s %s %s' % (
            '\nTerm', self.term.name, 'has action', str(self.term.action[0]),
            'with source_prefix or destination_prefix,',
            ' which is unsupported in iptables output.'))
      return ('# skipped %s due to source or destination prefix rule' %
              self.term.name)

    # protocol
    protocol = ['all']
    if self.term.protocol:
      protocol = self.term.protocol
    if self.term.protocol_except:
      raise UnsupportedFilter('%s %s %s' % (
          '\n', self.term.name,
          'protocol_except logic not currently supported.'))

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
    source_port = []
    destination_port = []
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port
    # because we are looping through ports, we must have something in each
    # so we replace an empty list with a list containing an empty string
    source_port = source_port or ['']
    destination_port = destination_port or ['']

    # icmp types
    icmp_types = []
    for icmp in self.term.icmp_type:
      if protocol != ['icmp']:
        raise UnsupportedFilter('%s %s %s %s' % (
            '\nMay not specify icmp_type for protocol',
            protocol, '\nError in term:', self.term.name))
      # Translate if needed, or pass verbatim otherwise.
      icmp_types.append(self._ICMP_POLICY_TO_NAMES.get(icmp, icmp))
    if not icmp_types:
      icmp_types = [None]

    # options
    tcp_flags = []
    for next in [str(x) for x in self.term.option]:
      #
      # Sanity checking and high-ports are added as appropriate in
      # pre-processing that is done in __str__ within class Iptables.
      # Option established will add destination port high-ports if protocol
      # contains only tcp, udp or both.  This is done earlier in class Iptables.
      #
      if self.trackstate:
        if (next.find('established') == 0
            and 'ESTABLISHED' not in [x.strip() for x in self.options]):
          self.options.append('-m state --state ESTABLISHED,RELATED')
      else:
        # nostate:
        # Using "--state ESTABLISHED" permits TCP connections that appear
        # to be ongoing sessions (e.g. SYN not set).  This doesn't require
        # new sessions to be added to conntrack with "-m state --state NEW"
        # This only works for TCP, since it can examine tcp-flags for state.
        #
        if (next.find('established') == 0 and protocol == ['tcp']
            and 'ESTABLISHED' not in [x.strip() for x in self.options]):
          self.options.append('-m state --state ESTABLISHED,RELATED')
      #
      # does the same as established but does not append high-ports to
      # destination ports
      if next.find('tcp-established') == 0:
        # only allow tcp-established if proto is explicitly 'tcp' only
        if protocol == ['tcp']:
          self.options.append('-m state --state ESTABLISHED,RELATED')
        else:
          raise TcpEstablishedError('%s %s %s' % (
              '\noption tcp-established can only be applied for proto tcp.',
              '\nError in term:', self.term.name))

      # Iterate through flags table, and create list of tcp-flags to append
      for next_flag in self._TCP_FLAGS_TABLE:
        if next.find(next_flag) == 0:
          tcp_flags.append(self._TCP_FLAGS_TABLE.get(next_flag))
      if next in self._KNOWN_OPTIONS_MATCHERS:
        self.options.append(self._KNOWN_OPTIONS_MATCHERS[next])
    if self.term.packet_length:
      # Policy format is "#-#", but iptables format is "#:#"
      self.options.append('-m length --length %s' %
                          self.term.packet_length.replace('-', ':'))
    if self.term.fragment_offset:
      self.options.append('-m u32 --u32 4&0x1FFF=%s' %
                          self.term.fragment_offset.replace('-', ':'))

    for saddr in term_saddr:
      for daddr in term_daddr:
        for sport in source_port:
          for dport in destination_port:
            for icmp in icmp_types:
              for proto in protocol:
                ret_str.append(self._FormatPart(
                    self.af,
                    str(proto),
                    saddr,
                    sport,
                    daddr,
                    dport,
                    self.options,
                    tcp_flags,
                    icmp,
                    self._ACTION_TABLE.get(str(self.term.action[0]))
                    ))

    # Add this term to the filters jump table
    ret_str.append('-A %s -j %s' % (self.filter, self.term_name))

    return '\n'.join(str(v) for v in ret_str if v is not '')

  def _FormatPart(self, af, protocol, saddr, sport, daddr, dport, options,
                  tcp_flags, icmp_type, action):
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
      icmp_type: What icmp protocol to allow, if any
      action: What should happen if this rule matches
    Returns:
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
    filter_top = '-A ' + self.term_name
    # fix addresses
    if saddr == self._all_ips:
      src = ''
    else:
      src = '-s %s/%d' % (saddr.ip, saddr.prefixlen)

    if daddr == self._all_ips:
      dst = ''
    else:
      dst = '-d %s/%d' % (daddr.ip, daddr.prefixlen)

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

    if not options:
      options = []

    proto = self._PROTO_TABLE.get(str(protocol))
    if protocol and not proto:  # Don't drop protocol if we don't recognize it
      proto = '-p %s' % str(protocol)
    # set conntrack state to NEW, unless policy requested "nostate"
    if self.trackstate:
      already_stateful = False
      # we will add new stateful arguments only if none already exist, such
      # as from "option:: established"
      for option in options:
        if 'state' in option:
          already_stateful = True
      if not already_stateful:
        if 'ACCEPT' in action:
          # We have to permit established/related since a policy may not
          # have an existing blank permit for established/related, which
          # may be more efficient, but slightly less secure.
          options.append('-m state --state NEW,ESTABLISHED,RELATED')

    if not tcp_flags:
      flags = ''
    else:
      flags = '--tcp-flags %s %s' % (','.join(tcp_flags), ','.join(tcp_flags))

    if not icmp_type:
      icmp = ''
    else:
      icmp = '--icmp-type %s' % icmp_type

    rval = [filter_top]
    for value in (proto, flags, sport, dport, icmp, src, dst, ' '.join(options),
                  action):
      if value:
        rval.append(str(value))
    return ' '.join(rval)

  def _CheckTermLength(self, term_name, term_max_len, abbreviate):
    """Return a name based on term_name which is shorter than term_max_len.

    Args:
      term_name: A name to abbreviate if necessary.
      term_max_len: An int representing the maximum acceptable length.
      abbreviate: whether to allow abbreviations to shorten the length
    Returns:
      A string based on term_name, abbreviated as necessary to fit term_max_len.
    Raises:
      TermNameTooLong: the term_name cannot be abbreviated below term_max_len.
    """
    # We use uppercase for abbreviations to distinguish from lowercase
    # names.  Ordered list of abbreviations, we try the ones in the
    # top of the list before the ones later in the list.  Prefer clear
    # or very-space-saving abbreviations by putting them early in the
    # list.  Abbreviations may be regular expressions or fixed terms;
    # prefer fixed terms unless there's a clear benefit to regular
    # expressions.
    abbreviation_table = [
        ('bogons', 'BGN'),
        ('bogon', 'BGN'),
        ('reserved', 'RSV'),
        ('rfc1918', 'PRV'),
        ('rfc-1918', 'PRV'),
        ('internet', 'EXT'),
        ('global', 'GBL'),
        ('internal', 'INT'),
        ('customer', 'CUST'),
        ('google', 'GOOG'),
        ('ballmer', 'ASS'),
        ('microsoft', 'LOL'),
        ('china', 'BAN'),
        ('border', 'BDR'),
        ('service', 'SVC'),
        ('router', 'RTR'),
        ('transit', 'TRNS'),
        ('experiment', 'EXP'),
        ('established', 'EST'),
        ('unreachable', 'UNR'),
        ('fragment', 'FRG'),
        ('accept', 'OK'),
        ('discard', 'DSC'),
        ('reject', 'REJ'),
        ('replies', 'ACK'),
        ('request', 'REQ'),
        ]
    new_term = term_name
    if abbreviate:
      for word, abbrev in abbreviation_table:
        if len(new_term) <= term_max_len:
          return new_term
        new_term = re.sub(word, abbrev, new_term)
    if len(new_term) <= term_max_len:
      return new_term
    raise TermNameTooLong('%s %s %s %s%s %d %s' % (
        '\nTerm', new_term, '(originally', term_name,
        ') is too long. Limit is 24 characters (vs', len(new_term),
        ') and no abbreviations remain.'))


class Iptables(object):
  """Generates filters and terms from provided policy object."""

  _SUFFIX = '.ipt'

  def __init__(self, pol):
    has_iptables = False
    for header in pol.headers:
      if 'iptables' in header.platforms:
        has_iptables = True
    if not has_iptables:
      raise NoIptablesPolicyError('%s %s' % (
          '\nNo iptables policy found in', header.target))
    self.policy = pol

  def __str__(self):
    target = []
    default_action = 'DROP'
    good_default_actions = ['ACCEPT', 'DROP']
    good_filters = ['INPUT', 'OUTPUT', 'FORWARD']
    good_afs = ['inet', 'inet6']
    good_options = ['nostate', 'truncatenames']
    trackstate = True
    filter_type = None

    target.append('*filter')
    for header, terms in self.policy.filters:
      if 'iptables' in header.platforms:
        filter_name = header.FilterName('iptables')
        if filter_name not in good_filters:
          logging.warn('%s %s %s %s' % (
              'Filter is generating a non-standard chain that will not ',
              'apply to traffic unless linked from INPUT, OUTPUT or ',
              'FORWARD filters. New chain name is: ', filter_name))
        filter_options = header.FilterOptions('iptables')[1:]
        # ensure all options after the filter name are expected
        for opt in filter_options:
          if opt not in good_default_actions + good_afs + good_options:
            raise UnsupportedTargetOption('%s %s' % (
                '\nUnsupported option found in iptables target definition:',
                opt))

        # disable stateful?
        if 'nostate' in filter_options:
          trackstate = False

        # Check for matching af
        for address_family in good_afs:
          if address_family in filter_options:
            # should not specify more than one AF in options
            if filter_type is not None:
              raise UnsupportedFilter('%s %s %s %s' % (
                  '\nMay only specify one of', good_afs, 'in filter options:',
                  filter_options))
            filter_type = address_family
        if filter_type is None:
          filter_type = 'inet'

        # does this policy override the default filter actions?
        for next in header.target:
          if next.platform == 'iptables':
            if len(next.options) > 1:
              for arg in next.options:
                if arg in good_default_actions:
                  default_action = arg
        if default_action not in good_default_actions:
          raise UnsupportedDefaultAction('%s %s %s' % (
              '\nOnly ACCEPT or DROP default filter action allowed;',
              default_action, 'used.'))

        # Add comments for this filter
        target.append('# Speedway Iptables %s Policy' %
                      header.FilterName('iptables'))
        # reformat long text comments, if needed
        comments = WrapWords(header.comment, 70)
        if comments and comments[0]:
          for line in comments:
            target.append('# %s' % line)
          target.append('#')
        # add the p4 tags
        p4_id = '$I' + 'd:$'
        p4_date = '$Da' + 'te:$'
        target.append('# %s' % p4_id)
        target.append('# %s' % p4_date)
        target.append('# ' + filter_type)

        # setup the default filter states.
        # if default action policy not specified, do nothing.
        if default_action:
          target.append(':%s %s' % (filter_name, default_action))

        # add the terms
        for term in terms:
          # established option implies high ports for tcp/udp
          for opt in [str(x) for x in term.option]:
            if opt.find('established') == 0:
              # if we don't specify a protocol apply to all protocols
              if not term.protocol: term.protocol = ['all']
              add_ports = True
              for proto in term.protocol:
                if proto not in ['tcp', 'udp']:
                  add_ports = False
                  #
                  # if we don't limit to just TCP and/or UDP, using
                  # 'option:: established' in a term could end up inadvertently
                  # becoming overly permissive.
                  #
                  if not trackstate:
                    raise EstablishedError('%s %s' % (
                        '\nYou have specified "option:: established" for'
                        'non-TCP/UDP protocols while specifying a stateless'
                        '(nostate) filter. This is only acceptable in stateful'
                        ' filters.\nError in term', term.name))
              # only add high-ports for TCP and/or UDP protocols
              if add_ports:
                # add in high ports, then collapse list to eliminate overlaps
                term.destination_port.append((1024, 65535))
          term.destination_port = term._CollapsePortList(term.destination_port)

          target.append(str(Term(term, filter_name, trackstate, default_action,
                                 filter_type, 'truncatenames' in filter_options)
                           ))
        target.append('\n')
      target.pop()  # remove extra \n
    target.append('COMMIT\n')
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


class EstablishedError(Error):
  """Raised when a term has established option with inappropriate protocol."""


class UnsupportedDefaultAction(Error):
  """Raised when a filter has an impermissible default action specified."""


class UnsupportedTargetOption(Error):
  """Raised when a filter has an impermissible default action specified."""
