# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Juniper JCL generator."""

import datetime
from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr
from capirca.lib import summarizer
import six


# generic error class
class Error(Exception):
  pass


class JuniperTermPortProtocolError(Error):
  pass


class TcpEstablishedWithNonTcpError(Error):
  pass


class JuniperDuplicateTermError(Error):
  pass


class UnsupportedFilterError(Error):
  pass


class PrecedenceError(Error):
  pass


class JuniperIndentationError(Error):
  pass


class JuniperNextIpError(Error):
  pass


class JuniperMultipleTerminatingActionError(Error):
  pass


class JuniperFragmentInV6Error(Error):
  pass


class Config:
  """Config allows a configuration to be assembled easily.

  Configurations are automatically indented following Juniper's style.
  A textual representation of the config can be extracted with str().

  Attributes:
    indent: The number of leading spaces on the current line.
    tabstop: The number of spaces to indent for a new level.
    lines: the text lines of the configuration.
  """

  def __init__(self, indent=0, tabstop=4):
    self.indent = indent
    self._initial_indent = indent
    self.tabstop = tabstop
    self.lines = []

  def __str__(self):
    if self.indent != self._initial_indent:
      raise JuniperIndentationError(
          'Expected indent %d but got %d' % (self._initial_indent, self.indent))
    return '\n'.join(self.lines)

  def Append(self, line, verbatim=False):
    """Append one line to the configuration.

    Args:
      line: The string to append to the config.
      verbatim: append line without adjusting indentation. Default False.
    Raises:
      JuniperIndentationError: If the indentation would be further left
        than the initial indent.  e.g. too many close braces.
    """
    if verbatim:
      self.lines.append(line)
      return

    if line.endswith('}'):
      self.indent -= self.tabstop
      if self.indent < self._initial_indent:
        raise JuniperIndentationError('Too many close braces.')
    spaces = ' ' * self.indent
    self.lines.append(spaces + line.strip())
    if not line.find('/*') >= 0 and line.find('*/') >= 0:
      self.indent -= 1
      if self.indent < self._initial_indent:
        raise JuniperIndentationError('Too many close comments.')
    if not line.find('*/') >= 0 and line.find('/*') >= 0:
      self.indent += 1
    if line.endswith(' {'):
      self.indent += self.tabstop


class Term(aclgenerator.Term):
  """Representation of an individual Juniper term.

    This is mostly useful for the __str__() method.
  Attributes:
    term: The term object from policy.
    term_type: String indicating type of term, inet, inet6 icmp etc.
    enable_dsmo: Boolean to enable dsmo.
    noverbose: Boolean to disable verbosity.
    filter_direction: Enum indicating the direction of the filter on an
      interface e.g. INGRESS.
    interface_type: Enum indicating the type of interface filter will be applied
      e.g. LOOPBACK.
  """
  _PLATFORM = 'juniper'
  _DEFAULT_INDENT = 12
  ACTIONS = {'accept': 'accept',
             'deny': 'discard',
             'reject': 'reject',
             'next': 'next term',
             'reject-with-tcp-rst': 'reject tcp-reset',
             'encapsulate': 'encapsulate',
             'decapsulate': 'decapsulate',
             'port-mirror': 'port-mirror'}

  # the following lookup table is used to map between the various types of
  # filters the juniper generator can render.  As new differences are
  # encountered, they should be added to this table.  Accessing members
  # of this table looks like:
  #  self._TERM_TYPE('inet').get('saddr') -> 'source-address'
  #
  # it's critical that the members of each filter type be the same, that is
  # to say that if _TERM_TYPE.get('inet').get('foo') returns something,
  # _TERM_TYPE.get('inet6').get('foo') must return the inet6 equivalent.
  _TERM_TYPE = {'inet': {'addr': 'address',
                         'saddr': 'source-address',
                         'daddr': 'destination-address',
                         'protocol': 'protocol',
                         'protocol-except': 'protocol-except',
                         'tcp-est': 'tcp-established'},
                'inet6': {'addr': 'address',
                          'saddr': 'source-address',
                          'daddr': 'destination-address',
                          'protocol': 'next-header',
                          'protocol-except': 'next-header-except',
                          'tcp-est': 'tcp-established'},
                'bridge': {'addr': 'ip-address',
                           'saddr': 'ip-source-address',
                           'daddr': 'ip-destination-address',
                           'protocol': 'ip-protocol',
                           'protocol-except': 'ip-protocol-except',
                           'tcp-est': 'tcp-flags "(ack|rst)"'}
              }

  def __init__(self, term, term_type, enable_dsmo, noverbose, filter_direction=None, interface_type=None):
    super().__init__(term)
    self.term = term
    self.term_type = term_type
    self.enable_dsmo = enable_dsmo
    self.noverbose = noverbose
    # Filter direction and interface type are needed in juniperevo sub-class for IPv6 filters.
    self.filter_direction = filter_direction
    self.interface_type = interface_type

    if self._PLATFORM != 'msmpc':
      if term_type not in self._TERM_TYPE:
        raise ValueError('Unknown Filter Type: %s' % term_type)
      if 'hopopt' in self.term.protocol:
        loc = self.term.protocol.index('hopopt')
        self.term.protocol[loc] = 'hop-by-hop'
      if 'hopopt' in self.term.protocol_except:
        loc = self.term.protocol_except.index('hopopt')
        self.term.protocol_except[loc] = 'hop-by-hop'

      # some options need to modify the actions
      self.extra_actions = []

  # TODO(pmoody): get rid of all of the default string concatenation here.
  #  eg, indent(8) + 'foo;' -> '%s%s;' % (indent(8), 'foo'). pyglint likes this
  #  more.
  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    config = Config(indent=self._DEFAULT_INDENT)
    from_str = []
    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.term_type == 'inet6' and 'icmp' in self.term.protocol) or
        (self.term_type == 'inet' and ('icmpv6' in self.term.protocol or
                                       'icmp6' in self.term.protocol))):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(
          term=self.term.name,
          proto=', '.join(self.term.protocol),
          af=self.term_type))
      return ''

    # comment
    # this deals just fine with multi line comments, but we could probably
    # output them a little cleaner; do things like make sure the
    # len(output) < 80, etc. Note, if 'noverbose' is set for the filter, skip
    # all comment processing.
    if self.term.owner and not self.noverbose:
      self.term.comment.append('Owner: %s' % self.term.owner)
    if self.term.comment and not self.noverbose:
      config.Append('/*')
      for comment in self.term.comment:
        for line in comment.split('\n'):
          config.Append('** ' + line)
      config.Append('*/')

    # Term verbatim output - this will skip over normal term creation
    # code.  Warning generated from policy.py if appropriate.
    if self.term.verbatim:
      for next_term in self.term.verbatim:
        if next_term[0] == self._PLATFORM:
          config.Append(str(next_term[1]), verbatim=True)
      return str(config)

    # Helper for per-address-family keywords.
    family_keywords = self._TERM_TYPE.get(self.term_type)

    # option
    # this is going to be a little ugly b/c there are a few little messed
    # up options we can deal with.
    if self.term.option:
      for opt in [str(x) for x in self.term.option]:
        # there should be a better way to search the array of protocols
        if opt.startswith('sample'):
          self.extra_actions.append('sample')

        # only append tcp-established for option established when
        # tcp is the only protocol, otherwise other protos break on juniper
        elif opt.startswith('established'):
          if self.term.protocol == ['tcp']:
            if 'tcp-established;' not in from_str:
              from_str.append(family_keywords['tcp-est'] + ';')

        # if tcp-established specified, but more than just tcp is included
        # in the protocols, raise an error
        elif opt.startswith('tcp-established'):
          flag = family_keywords['tcp-est'] + ';'
          if self.term.protocol == ['tcp']:
            if flag not in from_str:
              from_str.append(flag)
          else:
            raise TcpEstablishedWithNonTcpError(
                'tcp-established can only be used with tcp protocol in term %s'
                % self.term.name)
        elif opt.startswith('rst'):
          from_str.append('tcp-flags "rst";')
        elif opt.startswith('initial') and 'tcp' in self.term.protocol:
          from_str.append('tcp-initial;')
        elif opt.startswith('first-fragment'):
          from_str.append('first-fragment;')

        # we don't have a special way of dealing with this, so we output it and
        # hope the user knows what they're doing.
        else:
          from_str.append('%s;' % opt)

    # if the term is inactive we have to set the prefix
    if self.term.inactive:
      term_prefix = 'inactive:'
    else:
      term_prefix = ''

    # term name
    config.Append('%s term %s {' % (term_prefix, self.term.name))

    # The "filter" keyword is not compatible with from or then
    if self.term.filter_term:
      config.Append('filter %s;' % self.term.filter_term)
      config.Append('}')  # end term accept-foo-to-bar { ... }
      return str(config)

    # a default action term doesn't have any from { clause
    has_match_criteria = (self.term.address or
                          self.term.dscp_except or
                          self.term.dscp_match or
                          self.term.destination_address or
                          self.term.destination_port or
                          self.term.destination_prefix or
                          self.term.destination_prefix_except or
                          self.term.encapsulate or
                          self.term.ether_type or
                          self.term.flexible_match_range or
                          self.term.forwarding_class or
                          self.term.forwarding_class_except or
                          self.term.fragment_offset or
                          self.term.hop_limit or
                          self.term.next_ip or
                          self.term.port or
                          self.term.precedence or
                          self.term.protocol or
                          self.term.protocol_except or
                          self.term.source_address or
                          self.term.source_port or
                          self.term.source_prefix or
                          self.term.source_prefix_except or
                          self.term.traffic_type or
                          self.term.ttl)

    if has_match_criteria:
      config.Append('from {')

      term_af = self.AF_MAP.get(self.term_type)

      # address
      address = self.term.GetAddressOfVersion('address', term_af)
      if self.enable_dsmo:
        address = summarizer.Summarize(address)

      if address:
        config.Append('%s {' % family_keywords['addr'])
        for addr in address:
          for comment in self._Comment(addr):
            config.Append('%s' % comment)
          if self.enable_dsmo:
            config.Append('%s/%s;' % summarizer.ToDottedQuad(addr, nondsm=True))
          else:
            config.Append('%s;' % addr)
        config.Append('}')
      elif self.term.address:
        logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                     af=self.term_type))
        return ''

      # source address

      src_addr = self.term.GetAddressOfVersion('source_address', term_af)
      src_addr_ex = self.term.GetAddressOfVersion('source_address_exclude',
                                                  term_af)
      if self.enable_dsmo:
        src_addr = summarizer.Summarize(src_addr)
        src_addr_ex = summarizer.Summarize(src_addr_ex)
      else:
        src_addr, src_addr_ex = self._MinimizePrefixes(src_addr, src_addr_ex)

      if src_addr:
        config.Append('%s {' % family_keywords['saddr'])
        for addr in src_addr:
          for comment in self._Comment(addr):
            config.Append('%s' % comment)
          if self.enable_dsmo:
            config.Append('%s/%s;' % summarizer.ToDottedQuad(addr, nondsm=True))
          else:
            config.Append('%s;' % addr)
        for addr in src_addr_ex:
          for comment in self._Comment(addr, exclude=True):
            config.Append('%s' % comment)
          if self.enable_dsmo:
            config.Append('%s/%s except;' %
                          summarizer.ToDottedQuad(addr, nondsm=True))
          else:
            config.Append('%s except;' % addr)
        config.Append('}')
      elif self.term.source_address:
        logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                     direction='source',
                                                     af=self.term_type))
        return ''

      # destination address
      dst_addr = self.term.GetAddressOfVersion('destination_address', term_af)
      dst_addr_ex = self.term.GetAddressOfVersion('destination_address_exclude',
                                                  term_af)
      if self.enable_dsmo:
        dst_addr = summarizer.Summarize(dst_addr)
        dst_addr_ex = summarizer.Summarize(dst_addr_ex)
      else:
        dst_addr, dst_addr_ex = self._MinimizePrefixes(dst_addr, dst_addr_ex)

      if dst_addr:
        config.Append('%s {' % family_keywords['daddr'])
        for addr in dst_addr:
          for comment in self._Comment(addr):
            config.Append('%s' % comment)
          if self.enable_dsmo:
            config.Append('%s/%s;' % summarizer.ToDottedQuad(addr,
                                                             nondsm=True))
          else:
            config.Append('%s;' % addr)
        for addr in dst_addr_ex:
          for comment in self._Comment(addr, exclude=True):
            config.Append('%s' % comment)
          if self.enable_dsmo:
            config.Append('%s/%s except;' %
                          summarizer.ToDottedQuad(addr, nondsm=True))
          else:
            config.Append('%s except;' % addr)
        config.Append('}')
      elif self.term.destination_address:
        logging.debug(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                     direction='destination',
                                                     af=self.term_type))
        return ''

      # forwarding-class
      if self.term.forwarding_class:
        config.Append('forwarding-class %s' % self._Group(
            self.term.forwarding_class, lc=False))

      # forwarding-class-except
      if self.term.forwarding_class_except:
        config.Append('forwarding-class-except %s' % self._Group(
            self.term.forwarding_class_except, lc=False))

      # source prefix <except> list
      if self.term.source_prefix or self.term.source_prefix_except:
        config.Append('source-prefix-list {')
        for pfx in self.term.source_prefix:
          config.Append(pfx + ';')
        for epfx in self.term.source_prefix_except:
          config.Append(epfx + ' except;')
        config.Append('}')

      # destination prefix <except> list
      if self.term.destination_prefix or self.term.destination_prefix_except:
        config.Append('destination-prefix-list {')
        for pfx in self.term.destination_prefix:
          config.Append(pfx + ';')
        for epfx in self.term.destination_prefix_except:
          config.Append(epfx + ' except;')
        config.Append('}')

      # Only generate ttl if inet, inet6 uses hop-limit instead.
      if self.term.ttl and self.term_type == 'inet':
        config.Append('ttl %s;' % self.term.ttl)

      # port
      if self.term.port:
        config.Append('port %s' % self._Group(self.term.port))

      # source port
      if self.term.source_port:
        config.Append('source-port %s' % self._Group(self.term.source_port))

      # destination port
      if self.term.destination_port:
        config.Append('destination-port %s' %
                      self._Group(self.term.destination_port))

      # append any options beloging in the from {} section
      for next_str in from_str:
        config.Append(next_str)

      # packet length
      if self.term.packet_length:
        config.Append('packet-length %s;' % self.term.packet_length)

      # fragment offset
      if self.term.fragment_offset:
        config.Append('fragment-offset %s;' % self.term.fragment_offset)

      # icmp-types
      icmp_types = ['']
      if self.term.icmp_type:
        icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                             self.term.protocol, self.term_type)
      if icmp_types != ['']:
        config.Append('icmp-type %s' % self._Group(icmp_types))
      if self.term.icmp_code:
        config.Append('icmp-code %s' % self._Group(self.term.icmp_code))
      if self.term.ether_type:
        config.Append('ether-type %s' %
                      self._Group(self.term.ether_type))
      # protocol
      if self.term.protocol:
        # both are supported on JunOS, but only icmp6 is supported
        # on SRX loopback stateless filter, so set all instances of icmpv6 to icmp6.
        if 'icmpv6' in self.term.protocol:
          loc = self.term.protocol.index('icmpv6')
          self.term.protocol[loc] = 'icmp6'
        config.Append(family_keywords['protocol'] + ' ' +
                      self._Group(self.term.protocol))

      # protocol
      if self.term.protocol_except:
        # same as above
        if 'icmpv6' in self.term.protocol_except:
          loc = self.term.protocol_except.index('icmpv6')
          self.term.protocol_except[loc] = 'icmp6'
        config.Append(family_keywords['protocol-except'] + ' ' +
                      self._Group(self.term.protocol_except))

      if self.term.traffic_type:
        config.Append('traffic-type %s' %
                      self._Group(self.term.traffic_type))

      if self.term.precedence:
        # precedence may be a single integer, or a space separated list
        policy_precedences = set()
        # precedence values may only be 0 through 7
        for precedence in self.term.precedence:
          if int(precedence) in range(0, 8):
            policy_precedences.add(precedence)
          else:
            raise PrecedenceError('Precedence value %s is out of bounds in %s' %
                                  (precedence, self.term.name))
        config.Append('precedence %s' % self._Group(sorted(policy_precedences)))

      # DSCP Match
      if self.term.dscp_match:
        if self.term_type == 'inet6':
          config.Append('traffic-class [ %s ];' % (
              ' '.join(self.term.dscp_match)))
        else:
          config.Append('dscp [ %s ];' % ' '.join(self.term.dscp_match))

      # DSCP Except
      if self.term.dscp_except:
        if self.term_type == 'inet6':
          config.Append('traffic-class-except [ %s ];' % (
              ' '.join(self.term.dscp_except)))
        else:
          config.Append('dscp-except [ %s ];' % ' '.join(self.term.dscp_except))

      if self.term.hop_limit:
        # Only generate a hop-limit if inet6, inet4 has not hop-limit.
        if self.term_type == 'inet6':
          config.Append('hop-limit %s;' % (self.term.hop_limit))

      # flexible-match
      if self.term.flexible_match_range:
        config.Append('flexible-match-range {')
        for fm_opt in self.term.flexible_match_range:
          config.Append('%s %s;' % (fm_opt[0], fm_opt[1]))
        config.Append('}')

      config.Append('}')  # end from { ... }

    ####
    # ACTIONS go below here
    ####

    # If the action is only one line, include it in the same line as "then "
    # statement.
    # For example, if the action is only accept, it should be:
    # "then accept;" rather than:
    # "then {
    #     accept;
    # }"
    #
    self.CheckTerminatingAction()
    unique_actions = set(self.extra_actions)
    if not self.term.routing_instance:
      unique_actions.update(self.term.action)
    if self.term.encapsulate:
      unique_actions.add('encapsulate')
    if self.term.decapsulate:
      unique_actions.add('decapsulate')
    if len(unique_actions) <= 1:
      for action in [
          self.term.logging, self.term.routing_instance, self.term.counter,
          self.term.policer, self.term.qos, self.term.loss_priority,
          self.term.dscp_set, self.term.next_ip, self.term.traffic_class_count,
          self.term.port_mirror
      ]:
        if action:
          try:
            unique_actions.update(action)
          except TypeError:
            unique_actions.add(action)
          if len(unique_actions) > 1:
            break

    if len(unique_actions) == 1:
      # b/21795531: Juniper device treats a set of IPv4 actions differently
      # than any other actions.
      # For example, if the term is in IPv4 and the action is only discard,
      # it should be:
      # "then {
      #     discard;
      # }" rather than:
      # "then discard;"
      current_action = self.ACTIONS.get(unique_actions.pop(), 'next_ip')
      if (self.term_type == 'inet' and
          current_action in ['discard', 'reject', 'reject tcp-reset']
         ) or (self.term_type == 'inet6' and current_action in
               ['reject', 'reject tcp-reset']):
        config.Append('then {')
        config.Append('%s;' % current_action)
        config.Append('}')
      elif current_action == 'next_ip':
        self.NextIpCheck(self.term.next_ip, self.term.name)
        config.Append('then {')
        if self.term.next_ip[0].version == 4:
          config.Append('next-ip %s;' % str(self.term.next_ip[0]))
        else:
          config.Append('next-ip6 %s;' % str(self.term.next_ip[0]))
        config.Append('}')
      elif current_action == 'encapsulate':
        config.Append('then {')
        config.Append('encapsulate %s;' % str(self.term.encapsulate))
        config.Append('}')
      elif current_action == 'decapsulate':
        config.Append('then {')
        config.Append('decapsulate %s;' % str(self.term.decapsulate))
        config.Append('}')
      else:
        config.Append('then %s;' % current_action)
    elif len(unique_actions) > 1:
      config.Append('then {')
      # logging
      if self.term.logging:
        for log_target in self.term.logging:
          if str(log_target) == 'local':
            config.Append('log;')
          else:
            config.Append('syslog;')

      if self.term.routing_instance:
        config.Append('routing-instance %s;' % self.term.routing_instance)

      if self.term.counter:
        config.Append('count %s;' % self.term.counter)

      if self.term.traffic_class_count:
        config.Append('traffic-class-count %s;' % self.term.traffic_class_count)

      oid_length = 128
      if self.term.policer:
        config.Append('policer %s;' % self.term.policer)
        if len(self.term.policer) > oid_length:
          logging.warning('WARNING: %s is longer than %d bytes. Due to '
                          'limitation in JUNOS, OIDs longer than %dB can '
                          'cause SNMP timeout issues.',
                          self.term.policer, oid_length, oid_length)

      if self.term.qos:
        config.Append('forwarding-class %s;' % self.term.qos)

      if self.term.port_mirror:
        config.Append('port-mirror;')
      if self.term.loss_priority:
        config.Append('loss-priority %s;' % self.term.loss_priority)
      if self.term.next_ip:
        self.NextIpCheck(self.term.next_ip, self.term.name)
        if self.term.next_ip[0].version == 4:
          config.Append('next-ip %s;' % str(self.term.next_ip[0]))
        else:
          config.Append('next-ip6 %s;' % str(self.term.next_ip[0]))
      if self.term.encapsulate:
        config.Append('encapsulate %s;' % str(self.term.encapsulate))
      if self.term.decapsulate:
        config.Append('decapsulate %s;' % str(self.term.decapsulate))
      for action in self.extra_actions:
        config.Append(action + ';')

      # If there is a routing-instance defined, skip reject/accept/etc actions.
      if not self.term.routing_instance:
        for action in self.term.action:
          config.Append(self.ACTIONS.get(action) + ';')

      # DSCP SET
      if self.term.dscp_set:
        if self.term_type == 'inet6':
          config.Append('traffic-class %s;' % self.term.dscp_set)
        else:
          config.Append('dscp %s;' % self.term.dscp_set)

      config.Append('}')  # end then{...}

    config.Append('}')  # end term accept-foo-to-bar { ... }

    return str(config)

  @staticmethod
  def NextIpCheck(next_ip, term_name):
    if len(next_ip) > 1:
      raise JuniperNextIpError('The following term has more '
                               'than one next IP value: %s' % term_name)
    if next_ip[0].num_addresses > 1:
      raise JuniperNextIpError('The following term has a subnet '
                               'instead of a host: %s' % term_name)

  def CheckTerminatingAction(self):
    action = set(self.term.action)
    if self.term.encapsulate:
      action.add(self.term.encapsulate)
    if self.term.decapsulate:
      action.add(self.term.decapsulate)
    if self.term.routing_instance:
      action.add(self.term.routing_instance)
    if len(action) > 1:
      raise JuniperMultipleTerminatingActionError(
          'The following term has multiple terminating actions: %s' %
          self.term.name)

  def _MinimizePrefixes(self, include, exclude):
    """Calculate a minimal set of prefixes for Juniper match conditions.

    Args:
      include: Iterable of nacaddr objects, prefixes to match.
      exclude: Iterable of nacaddr objects, prefixes to exclude.
    Returns:
      A tuple (I,E) where I and E are lists containing the minimized
      versions of include and exclude, respectively.  The order
      of each input list is preserved.
    """
    # Remove any included prefixes that have EXACT matches in the
    # excluded list.  Excluded prefixes take precedence on the router
    # regardless of the order in which the include/exclude are applied.
    exclude_set = set(exclude)
    include_result = [ip for ip in include if ip not in exclude_set]

    # Every address match condition on a Juniper firewall filter
    # contains an implicit "0/0 except" or "0::0/0 except".  If an
    # excluded prefix is not contained within any less-specific prefix
    # in the included set, we can elide it.  In other words, if the
    # next-less-specific prefix is the implicit "default except",
    # there is no need to configure the more specific "except".
    #
    # TODO(kbrint): this could be made more efficient with a Patricia trie.
    exclude_result = []
    for exclude_prefix in exclude:
      for include_prefix in include_result:
        if exclude_prefix.subnet_of(include_prefix):
          exclude_result.append(exclude_prefix)
          break

    return include_result, exclude_result

  def _Comment(self, addr, exclude=False, line_length=132):
    """Returns address comment field if it exists.

    Args:
      addr: nacaddr.IPv4 object (?)
      exclude: bool - address excludes have different indentations
      line_length: integer - this is the length to which a comment will be
        truncated, no matter what.  ie, a 1000 character comment will be
        truncated to line_length, and then split.  if 0, the whole comment
        is kept. the current default of 132 is somewhat arbitrary.

    Returns:
      List of strings.

    Notes:
      This method tries to intelligently split long comments up.  if we've
      managed to summarize 4 /32's into a /30, each with a nacaddr text field
      of something like 'foobar N', normal concatination would make the
      resulting rendered comment look in mondrian like

                         source-address {
                             ...
                             1.1.1.0/30; /* foobar1, foobar2, foobar3, foo
      bar4 */

      b/c of the line splitting at 80 chars.  this method will split the
      comments at word breaks and make the previous example look like

                         source-address {
                              ....
                              1.1.1.0/30; /* foobar1, foobar2, foobar3,
                                          ** foobar4 */
      much cleaner.
    """
    rval = []
    if self.noverbose:
      return rval
    # indentation, for multi-line comments, ensures that subsquent lines
    # are correctly alligned with the first line of the comment.
    indentation = 0
    if exclude:
      # len('1.1.1.1/32 except;') == 21
      indentation = 21 + self._DEFAULT_INDENT
    else:
      # len('1.1.1.1/32;') == 14
      indentation = 14 + self._DEFAULT_INDENT

    # length_eol is the width of the line; b/c of the addition of the space
    # and the /* characters, it needs to be a little less than the actual width
    # to keep from wrapping
    length_eol = 77 - indentation

    if isinstance(addr, (nacaddr.IPv4, nacaddr.IPv6, summarizer.DSMNet)):
      if addr.text:

        if line_length == 0:
          # line_length of 0 means that we don't want to truncate the comment.
          line_length = len(addr.text)

        # There should never be a /* or */, but be safe and ignore those
        # comments
        if addr.text.find('/*') >= 0 or addr.text.find('*/') >= 0:
          logging.debug('Malformed comment [%s] ignoring', addr.text)
        else:

          text = addr.text[:line_length]

          comment = ' /*'
          while text:
            # split the line
            if len(text) > length_eol:
              new_length_eol = text[:length_eol].rfind(' ')
              if new_length_eol <= 0:
                new_length_eol = length_eol
            else:
              new_length_eol = length_eol

            # what line am I gunna output?
            line = comment + ' ' + text[:new_length_eol].strip()
            # truncate what's left
            text = text[new_length_eol:]
            # setup the comment and indentation for the next go-round
            comment = ' ' * indentation + '**'

            rval.append(line)

          rval[-1] += ' */'
    else:
      # should we be paying attention to any other addr type?
      logging.debug('Ignoring non IPv4 or IPv6 address: %s', addr)
    return rval

  def _Group(self, group, lc=True):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of
             tuples (ports)
      lc: return a lower cased result for text.  Default is True.

    Returns:
      rval: a string surrounded by '[' and '];' if len(group) > 1
            or with just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el, lc=True):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string (protocol) or a tuple (ports)
        lc: return lower cased result for text.  Default is True.

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str) or isinstance(el, str):
        if lc:
          return el
        else:
          return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return '%d' % el[0]
      else:
        return '%d-%d' % (el[0], el[1])

    if len(group) > 1:
      rval = '[ ' + ' '.join([_FormattedGroup(x) for x in group]) + ' ];'
    else:
      rval = _FormattedGroup(group[0]) + ';'
    return rval


class Juniper(aclgenerator.ACLGenerator):
  """JCL rendering class.

    This class takes a policy object and renders the output into a syntax
    which is understood by juniper routers.

  Attributes:
    pol: policy.Policy object
  """

  _PLATFORM = 'juniper'
  _DEFAULT_PROTOCOL = 'ip'
  _SUPPORTED_AF = frozenset(('inet', 'inet6', 'bridge', 'mixed'))
  _TERM = Term
  SUFFIX = '.jcl'

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'address',
                         'restrict_address_family',
                         'counter',
                         'decapsulate',
                         'destination_prefix',
                         'destination_prefix_except',
                         'dscp_except',
                         'dscp_match',
                         'dscp_set',
                         'encapsulate',
                         'ether_type',
                         'filter_term',
                         'flexible_match_range',
                         'forwarding_class',
                         'forwarding_class_except',
                         'fragment_offset',
                         'hop_limit',
                         'icmp_code',
                         'logging',
                         'loss_priority',
                         'next_ip',
                         'owner',
                         'packet_length',
                         'policer',
                         'port',
                         'port_mirror',
                         'precedence',
                         'protocol_except',
                         'qos',
                         'routing_instance',
                         'source_prefix',
                         'source_prefix_except',
                         'traffic_type',
                         'traffic_class_count',
                         'ttl'}
    supported_sub_tokens.update({
        'option': {
            'established',
            'first-fragment',
            'is-fragment',
            # TODO(sneakywombat): add all options to lex.
            '.*',  # make ArbitraryOptions work, yolo.
            'sample',
            'tcp-established',
            'tcp-initial',
            'inactive'}
         })
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    self.juniper_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      # Check for the position independent options and remove them from
      # the list.
      interface_specific = 'not-interface-specific' not in filter_options[1:]
      enable_dsmo = 'enable_dsmo' in filter_options[1:]
      noverbose = 'noverbose' in filter_options[1:]
      filter_enhanced_mode = 'filter_enhanced_mode' in filter_options[1:]

      filter_direction = None
      if 'ingress' in filter_options[1:]:
        filter_direction = 'ingress'
      elif 'egress' in filter_options[1:]:
        filter_direction = 'egress'
      interface_type = None
      if 'physical' in filter_options[1:]:
        interface_type = 'physical'
      elif 'loopback' in filter_options[1:]:
        interface_type = 'loopback'

      if not interface_specific:
        filter_options.remove('not-interface-specific')
      if enable_dsmo:
        filter_options.remove('enable_dsmo')
      if filter_enhanced_mode:
        filter_options.remove('filter_enhanced_mode')

      # default to inet4 filters
      filter_type = 'inet'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      if filter_type == 'mixed':
        filter_types_to_process = ['inet', 'inet6']
      else:
        filter_types_to_process = [filter_type]

      for filter_type in filter_types_to_process:

        filter_name_suffix = ''
        # If mixed filter_type, will append 4 or 6 to the filter name
        if len(filter_types_to_process) > 1:
          if filter_type == 'inet':
            filter_name_suffix = '4'
          if filter_type == 'inet6':
            filter_name_suffix = '6'

        term_names = set()
        new_terms = []
        for term in terms:

          # Ignore if the term is for a different AF
          if term.restrict_address_family and term.restrict_address_family != filter_type:
            continue

          # if inactive is set, deactivate the term and remove the option.
          if 'inactive' in term.option:
            term.inactive = True
            term.option.remove('inactive')

          term.name = self.FixTermLength(term.name)

          if term.name in term_names:
            raise JuniperDuplicateTermError('You have multiple terms named: %s' %
                                            term.name)
          term_names.add(term.name)

          term = self.FixHighPorts(term, af=filter_type)
          if not term:
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info('INFO: Term %s in policy %s expires '
                          'in less than two weeks.', term.name, filter_name)
            if term.expiration <= current_date:
              logging.warning('WARNING: Term %s in policy %s is expired and '
                              'will not be rendered.', term.name, filter_name)
              continue
          if 'is-fragment' in term.option and filter_type == 'inet6':
            raise JuniperFragmentInV6Error('The term %s uses "is-fragment" but '
                                          'is a v6 policy.' % term.name)

          new_terms.append(self._TERM(term, filter_type, enable_dsmo, noverbose, filter_direction, interface_type))

        self.juniper_policies.append((header, filter_name + filter_name_suffix, filter_type,
                                      interface_specific, filter_enhanced_mode, new_terms))

  def __str__(self):
    config = Config()

    for (header, filter_name, filter_type, interface_specific, filter_enhanced_mode, terms
        ) in self.juniper_policies:
      # add the header information
      config.Append('firewall {')
      config.Append('family %s {' % filter_type)
      config.Append('/*')

      # we want the acl to contain id and date tags, but p4 will expand
      # the tags here when we submit the generator, so we have to trick
      # p4 into not knowing these words.  like taking c-a-n-d-y from a
      # baby.
      for line in aclgenerator.AddRepositoryTags('** '):
        config.Append(line)
      config.Append('**')

      for comment in header.comment:
        for line in comment.split('\n'):
          config.Append('** ' + line)
      config.Append('*/')

      config.Append('replace: filter %s {' % filter_name)
      if interface_specific:
        config.Append('interface-specific;')
      if filter_enhanced_mode:
        config.Append('enhanced-mode;')

      for term in terms:
        term_str = str(term)
        if term_str:
          config.Append(term_str, verbatim=True)

      config.Append('}')  # filter { ... }
      config.Append('}')  # family inet { ... }
      config.Append('}')  # firewall { ... }

    return str(config) + '\n'
