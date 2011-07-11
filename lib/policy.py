#!/usr/bin/python
#
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

"""Parses the generic policy files and return a policy object for acl rendering.
"""

import os
import sys

import nacaddr
import naming

from third_party.ply import lex
from third_party.ply import yacc


DEFINITIONS = None
DEFAULT_DEFINITIONS = './def'
_ACTIONS = set(('accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'))
_LOGGING = set(('true', 'True', 'syslog', 'local'))
_OPTIMIZE = True


class Error(Exception):
  """Generic error class."""


class FileNotFoundError(Error):
  """Policy file unable to be read."""


class FileReadError(Error):
  """Policy file unable to be read."""


class RecursionTooDeepError(Error):
  """Included files exceed maximum recursion depth."""


class ParseError(Error):
  """ParseError in the input."""


class TermAddressExclusionError(Error):
  """Excluded address block is not contained in the accepted address block."""


class TermObjectTypeError(Error):
  """Error with an object passed to Term."""


class TermPortProtocolError(Error):
  """Error when a requested protocol doesn't have any of the requested ports."""


class TermProtocolEtherTypeError(Error):
  """Error when both ether-type & upper-layer protocol matches are requested."""


class TermNoActionError(Error):
  """Error when a term hasn't defined an action."""


class TermInvalidIcmpType(Error):
  """Error when a term has invalid icmp-types specified."""


class InvalidTermActionError(Error):
  """Error when an action is invalid."""


class InvalidTermLoggingError(Error):
  """Error when a option is set for logging."""


class UndefinedAddressError(Error):
  """Error when an undefined address is referenced."""


class NoTermsError(Error):
  """Error when no terms were found."""


def TranslatePorts(ports, protocols):
  """Return all ports of all protocols requested.

  Args:
    ports: list of ports, eg ['SMTP', 'DNS']
    protocols: list of protocols, eg ['tcp', 'udp']

  Returns:
    ret_array: list of ports ['25, '53', '53']

  Note:
    Duplication will be taken care of in Term.CollapsePortList
  """
  ret_array = []
  for proto in protocols:
    for port in ports:
      for p in [x.split('-') for x in DEFINITIONS.GetServiceByProto(
          port, proto)]:
        if len(p) == 1:
          ret_array.append((int(p[0]), int(p[0])))
        else:
          ret_array.append((int(p[0]), int(p[1])))
  return ret_array


# classes for storing the object types in the policy files.
class Policy(object):
  """The policy object contains everything found in a given policy file.

  members:
    header: __main__.Header object. contains comments which should be passed
      on to the rendered acls as well as the type of acls this policy file
      should render to.

    terms: list __main__.Term. an array of Term objects which must be rendered
      in each of the rendered acls.
  """

  def __init__(self, header, terms):
    self.filters = []
    self.AddFilter(header, terms)

  def AddFilter(self, header, terms):
    """Add another header & term."""
    self.filters.append((header, terms))
    self._TranslateTerms(terms)

  def _TranslateTerms(self, terms):
    """."""
    if not terms:
      raise NoTermsError('no terms found')
    for term in terms:
      # TODO(pmoody): this probably belongs in Term.SanityCheck(),
      # or at the very least, in some method under class Term()
      if term.translated:
        continue
      if term.port:
        term.port = TranslatePorts(term.port, term.protocol)
        if not term.port:
          raise TermPortProtocolError(
              'no ports of the correct protocol for term %s' % (
                  term.name))
      if term.source_port:
        term.source_port = TranslatePorts(term.source_port, term.protocol)
        if not term.source_port:
          raise TermPortProtocolError(
              'no source ports of the correct protocol for term %s' % (
                  term.name))
      if term.destination_port:
        term.destination_port = TranslatePorts(term.destination_port,
                                               term.protocol)
        if not term.destination_port:
          raise TermPortProtocolError(
              'no destination ports of the correct protocol for term %s' % (
                  term.name))

      # If argument is true, we optimize, otherwise just sort addresses
      term.AddressCleanup(_OPTIMIZE)
      term.SanityCheck()
      term.translated = True

  @property
  def headers(self):
    """Returns the headers from each of the configured filters.

    Returns:
      headers
    """
    return map(lambda x: x[0], self.filters)


class Term(object):
  """The Term object is used to store each of the terms.

  Args:
    obj: an object of type VarType or a list of objects of type VarType

  members:
    address/source_address/destination_address: list of
      VarType.(S|D)?ADDRESS's
    port/source_port/destination_port: list of VarType.(S|D)?PORT's
    options: list of VarType.OPTION's.
    protocol: list of VarType.PROTOCOL's.
    counter: VarType.COUNTER
    action: list of VarType.ACTION's
    comments: VarType.COMMENT
    verbatim: VarType.VERBATIM
    logging: VarType.LOGGING
    qos: VarType.QOS
    policer: VarType.POLICER
  """
  ICMP_TYPE = {4: {'echo-reply': 0,
                   'unreachable': 3,
                   'source-quench': 4,
                   'redirect': 5,
                   'alternate-address': 6,
                   'echo-request': 8,
                   'router-advertisement': 9,
                   'router-solicitation': 10,
                   'time-exceeded': 11,
                   'parameter-problem': 12,
                   'timestamp-request': 13,
                   'timestamp-reply': 14,
                   'information-request': 15,
                   'information-reply': 16,
                   'mask-request': 17,
                   'mask-reply': 18,
                   'conversion-error': 31,
                   'mobile-redirect': 32,
                  },
               6: {'destination-unreachable': 1,
                   'packet-too-big': 2,
                   'time-exceeded': 3,
                   'parameter-problem': 4,
                   'echo-request': 128,
                   'echo-reply': 129,
                   'multicast-listener-query': 130,
                   'multicast-listener-report': 131,
                   'multicast-listener-done': 132,
                   'router-solicit': 133,
                   'router-advertisement': 134,
                   'neighbor-solicit': 135,
                   'neighbor-advertisement': 136,
                   'redirect-message': 137,
                   'router-renumbering': 138,
                   'icmp-node-information-query': 139,
                   'icmp-node-information-response': 140,
                   'inverse-neighbor-discovery-solicitation': 141,
                   'inverse-neighbor-discovery-advertisement': 142,
                   'version-2-multicast-listener-report': 143,
                   'home-agent-address-discovery-request': 144,
                   'home-agent-address-discovery-reply': 145,
                   'mobile-prefix-solicitation': 146,
                   'mobile-prefix-advertisement': 147,
                   'certification-path-solicitation': 148,
                   'certification-path-advertisement': 149,
                   'multicast-router-advertisement': 151,
                   'multicast-router-solicitation': 152,
                   'multicast-router-termination': 153,
                  },
              }

  def __init__(self, obj):
    self.name = None

    self.action = []
    self.address = []
    self.comment = []
    self.counter = None
    self.destination_address = []
    self.destination_address_exclude = []
    self.destination_port = []
    self.destination_prefix = []
    self.logging = []
    self.loss_priority = None
    self.option = []
    self.policer = None
    self.port = []
    self.precedence = None
    self.protocol = []
    self.protocol_except = []
    self.qos = None
    self.routing_instance = None
    self.source_address = []
    self.source_address_exclude = []
    self.source_port = []
    self.source_prefix = []
    self.verbatim = []
    # juniper specific.
    self.packet_length = None
    self.fragment_offset = None
    self.icmp_type = []
    self.ether_type = []
    self.traffic_type = []
    self.translated = False
    # iptables specific
    self.source_interface = None

    self.AddObject(obj)

  def __contains__(self, other):
    """Determine if other term is contained in this term."""
    if self.verbatim or other.verbatim:
      # short circuit these
      if sorted(self.verbatim) is not sorted(other.verbatim):
        return False

    # check prototols
    if not self.CheckProtocolIsSuperset(self.protocol, other.protocol):
      return False
    if not self.CheckProtocolIsSuperset(other.protocol_except,
                                        self.protocol_except):
      return False

    # check addresses
    # the address directive is a special case mean either source or destination
    # address
    if self.address:
      if not (self.CheckAddressIsSuperset(self.address, other.address) or
              self.CheckAddressIsSuperset(self.address, other.source_address) or
              self.CheckAddressIsSuperset(self.address,
                                          other.destination_address)):
        return False
    else:
      if not self.CheckAddressIsSuperset(self.source_address,
                                         other.source_address):
        return False
      if not other.CheckAddressIsSuperset(other.source_address_exclude,
                                          self.source_address_exclude):
        return False
      if not self.CheckAddressIsSuperset(self.destination_address,
                                         other.destination_address):
        return False

      if not other.CheckAddressIsSuperset(other.destination_address_exclude,
                                          self.destination_address_exclude):
        return False

    # check ports
    # like the address directive, the port directive is special in that it can
    # be either source or destination.
    if self.port:
      if not (self.CheckPortIsSuperset(self.port, other.port) or
              self.CheckPortIsSuperset(self.port, other.source_port) or
              self.CheckPortIsSuperset(self.port, other.destination_port)):
        return False
    else:
      if not self.CheckPortIsSuperset(self.source_port, other.source_port):
        return False
      if not self.CheckPortIsSuperset(self.destination_port,
                                      other.destination_port):
        return False

    # prefix lists
    if self.source_prefix:
      if sorted(self.source_prefix) is not sorted(other.source_prefix):
        return False
    if self.destination_prefix:
      if sorted(self.destination_prefix) is not sorted(
          other.destination_prefix):
        return False

    # check various options
    for opt in self.option:
      if not opt in other.option:
        return False
    if self.fragment_offset:
      # fragment_offset looks like 'integer-integer' or just, 'integer'
      sfo = [int(x) for x in self.fragment_offset.split('-')]
      if other.fragment_offset:
        ofo = [int(x) for x in other.fragment_offset.split('-')]
        if sfo[0] < ofo[0] or sorted(sfo[1:]) > sorted(ofo[1:]):
          return False
      else:
        return False
    if self.packet_length:
      # packet_length looks like 'integer-integer' or just, 'integer'
      spl = [int(x) for x in self.packet_length.split('-')]
      if other.packet_length:
        opl = [int(x) for x in other.packet_length.split('-')]
        if spl[0] < opl[0] or sorted(spl[1:]) > sorted(opl[1:]):
          return False
      else:
        return False
    if self.icmp_type:
      if sorted(self.icmp_type) is not sorted(other.icmp_type):
        return False

    # we have containment
    return True

  def __str__(self):
    ret_str = []
    ret_str.append(' name: %s' % self.name)
    if self.address:
      ret_str.append('  address: %s' % self.address)
    if self.source_address:
      ret_str.append('  source_address: %s' % self.source_address)
    if self.source_address_exclude:
      ret_str.append('  source_address_exclude: %s' %
                     self.source_address_exclude)
    if self.destination_address:
      ret_str.append('  destination_address: %s' % self.destination_address)
    if self.destination_address_exclude:
      ret_str.append('  destination_address_exclude: %s' %
                     self.destination_address_exclude)
    if self.source_prefix:
      ret_str.append('  source_prefix: %s' % self.source_prefix)
    if self.destination_prefix:
      ret_str.append('  destination_prefix: %s' % self.destination_prefix)
    if self.protocol:
      ret_str.append('  protocol: %s' % self.protocol)
    if self.port:
      ret_str.append('  port: %s' % self.port)
    if self.source_port:
      ret_str.append('  source_port: %s' % self.source_port)
    if self.destination_port:
      ret_str.append('  destination_port: %s' % self.destination_port)
    if self.action:
      ret_str.append('  action: %s' % self.action)
    if self.option:
      ret_str.append('  option: %s' % self.option)
    if self.qos:
      ret_str.append('  qos: %s' % self.qos)
    if self.logging:
      ret_str.append('  logging: %s' % self.logging)
    if self.counter:
      ret_str.append('  counter: %s' % self.counter)
    if self.source_interface:
      ret_str.append('  source_interface: %s' % self.source_interface)
    return '\n'.join(ret_str)

  def __eq__(self, other):
    # action
    if not sorted(self.action) == sorted(other.action):
      return False

    # addresses.
    if not (sorted(self.address) == sorted(other.address) and
            sorted(self.source_address) == sorted(other.source_address) and
            sorted(self.source_address_exclude) ==
            sorted(other.source_address_exclude) and
            sorted(self.destination_address) ==
            sorted(other.destination_address) and
            sorted(self.destination_address_exclude) ==
            sorted(other.destination_address_exclude)):
      return False

    # prefix lists
    if not (sorted(self.source_prefix) == sorted(other.source_prefix) and
            sorted(self.destination_prefix) ==
            sorted(other.destination_prefix)):
      return False

    # ports
    if not (sorted(self.port) == sorted(other.port) and
            sorted(self.source_port) == sorted(other.source_port) and
            sorted(self.destination_port) == sorted(other.destination_port)):
      return False

    # protocol
    if not (sorted(self.protocol) == sorted(other.protocol) and
            sorted(self.protocol_except) == sorted(other.protocol_except)):
      return False

    # option
    if not sorted(self.option) == sorted(other.option):
      return False

    # qos
    if not self.qos == other.qos:
      return False

    # verbatim
    if not self.verbatim == other.verbatim:
      return False

    # policer
    if not self.policer == other.policer:
      return False

    # interface
    if not self.source_interface == other.source_interface:
      return False

    if not sorted(self.logging) == sorted(other.logging):
      return False
    if not self.qos == other.qos:
      return False
    if not self.packet_length == other.packet_length:
      return False
    if not self.fragment_offset == other.fragment_offset:
      return False
    if not sorted(self.icmp_type) == sorted(other.icmp_type):
      return False
    if not sorted(self.ether_type) == sorted(other.ether_type):
      return False
    if not sorted(self.traffic_type) == sorted(other.traffic_type):
      return False

    return True

  def __ne__(self, other):
    return not self.__eq__(other)

  def GetAddressOfVersion(self, addr_type, af=None):
    """Returns addresses of the appropriate Address Family.

    Args:
      addr_type: string, this will be either
        'source_address', 'source_address_exclude',
        'destination_address' or 'destination_address_exclude'
      af: int or None, either Term.INET4 or Term.INET6

    Returns:
      list of addresses of the correct family.
    """
    if not af:
      return eval('self.' + addr_type)

    return filter(lambda x: x.version == af, eval('self.' + addr_type))

  def AddObject(self, obj):
    """Add an object of unknown type to this term.

    Args:
      obj: single or list of either
        [Address, Port, Option, Protocol, Counter, Action, Comment]

    Raises:
      InvalidTermActionError: if the action defined isn't an accepted action.
        eg, action:: godofoobar
      TermObjectTypeError: if AddObject is called with an object it doesn't
        understand.
      InvalidTermLoggingError: when a option is set for logging not known.
    """
    if type(obj) is list:
      for x in obj:
        # do we have a list of addresses?
        if x.var_type is VarType.SADDRESS:
          self.source_address.extend(DEFINITIONS.GetNetAddr(x.value))
        elif x.var_type is VarType.DADDRESS:
          self.destination_address.extend(DEFINITIONS.GetNetAddr(x.value))
        elif x.var_type is VarType.ADDRESS:
          self.address.extend(DEFINITIONS.GetNetAddr(x.value))
        # do we have address excludes?
        elif x.var_type is VarType.SADDREXCLUDE:
          self.source_address_exclude.extend(DEFINITIONS.GetNetAddr(x.value))
        elif x.var_type is VarType.DADDREXCLUDE:
          self.destination_address_exclude.extend(
              DEFINITIONS.GetNetAddr(x.value))
        # do we have a list of ports?
        elif x.var_type is VarType.SPORT:
          self.source_port.append(x.value)
        elif x.var_type is VarType.DPORT:
          self.destination_port.append(x.value)
        # do we have a list of protocols?
        elif x.var_type is VarType.PROTOCOL:
          self.protocol.append(x.value)
        # do we have a list of protocol-exceptions?
        elif x.var_type is VarType.PROTOCOL_EXCEPT:
          self.protocol_except.append(x.value)
        # do we have a list of options?
        elif x.var_type is VarType.OPTION:
          self.option.append(x.value)
        elif x.var_type is VarType.SPFX:
          self.source_prefix.append(x.value)
        elif x.var_type is VarType.DPFX:
          self.destination_prefix.append(x.value)
        elif x.var_type is VarType.ETHER_TYPE:
          self.ether_type.append(x.value)
        elif x.var_type is VarType.TRAFFIC_TYPE:
          self.traffic_type.append(x.value)
        else:
          raise TermObjectTypeError(
              '%s isn\'t a type I know how to deal with (contains \'%s\')' % (
                  type(x), x.value))
    else:
      # stupid no switch statement in python
      if obj.var_type is VarType.COMMENT:
        self.comment.append(str(obj))
      elif obj.var_type is VarType.LOSS_PRIORITY:
        self.loss_priority = obj.value
      elif obj.var_type is VarType.ROUTING_INSTANCE:
        self.routing_instance = obj.value
      elif obj.var_type is VarType.PRECEDENCE:
        self.precedence = int(obj.value)
      elif obj.var_type is VarType.VERBATIM:
        self.verbatim.append(obj)
      elif obj.var_type is VarType.ACTION:
        if str(obj) not in _ACTIONS:
          raise InvalidTermActionError('%s is not a valid action' % obj)
        self.action.append(obj.value)
      elif obj.var_type is VarType.COUNTER:
        self.counter = obj
      elif obj.var_type is VarType.ICMP_TYPE:
        self.icmp_type.extend(obj.value)
      elif obj.var_type is VarType.LOGGING:
        if str(obj) not in _LOGGING:
          raise InvalidTermLoggingError('%s is not a valid logging option' %
                                        obj)
        self.logging.append(obj)
      # police man, tryin'a take you jail
      elif obj.var_type is VarType.POLICER:
        self.policer = obj.value
      # qos?
      elif obj.var_type is VarType.QOS:
        self.qos = obj.value
      elif obj.var_type is VarType.PACKET_LEN:
        self.packet_length = obj.value
      elif obj.var_type is VarType.FRAGMENT_OFFSET:
        self.fragment_offset = obj.value
      elif obj.var_type is VarType.SINTERFACE:
        self.source_interface = obj.value
      else:
        raise TermObjectTypeError(
            '%s isn\'t a type I know how to deal with' % (type(obj)))

  def SanityCheck(self):
    """Sanity check the definition of the term.

    Raises:
      ParseError: if term has both verbatim and non-verbatim tokens
      TermInvalidIcmpType: if term has invalid icmp-types specified
      TermNoActionError: if the term doesn't have an action defined.
      TermPortProtocolError: if the term has a service/protocol definition pair
        which don't match up, eg. SNMP and tcp
      TermAddressExclusionError: if one of the *-exclude directives is defined,
        but that address isn't contained in the non *-exclude directive. eg:
        source-address::CORP_INTERNAL source-exclude:: LOCALHOST
      TermProtocolEtherTypeError: if the term has both ether-type and
        upper-layer protocol restrictions
      InvalidTermActionError: action and routing-instance both defined

    This should be called when the term is fully formed, and
    all of the options are set.

    """
    if self.verbatim:
      if (self.action or self.source_port or self.destination_port or
          self.port or self.protocol or self.option):
        raise ParseError(
            'term "%s" has both verbatim and non-verbatim tokens.' % self.name)
    else:
      if not self.action and not self.routing_instance:
        raise TermNoActionError('no action specified for term %s' % self.name)
      if self.action and self.routing_instance:
        raise InvalidTermActionError('action:: and routing-instance:: can\'t ' +
                                     'both be defined for term %s' % self.name)
      # have we specified a port with a protocol that doesn't support ports?
      if self.source_port or self.destination_port or self.port:
        if 'tcp' not in self.protocol and 'udp' not in self.protocol:
          raise TermPortProtocolError(
              'ports specified with a protocol that doesn\'t support ports. '
              'Term: %s ' % self.name)
    # TODO(pmoody): do we have mutually exclusive options?
    # eg. tcp-established + tcp-initial?

    if self.ether_type and (
        self.protocol or
        self.address or
        self.destination_address or
        self.destination_address_exclude or
        self.destination_port or
        self.destination_prefix or
        self.source_address or
        self.source_address_exclude or
        self.source_port or
        self.source_prefix):
      raise TermProtocolEtherTypeError(
          'ether-type not supported when used with upper-layer protocol '
          'restrictions. Term: %s' % self.name)
    # validate icmp-types if specified, but addr_family will have to be checked
    # in the generators as policy module doesn't know about that at this point.
    if self.icmp_type:
      for icmptype in self.icmp_type:
        if (icmptype not in self.ICMP_TYPE[4] and icmptype not in
            self.ICMP_TYPE[6]):
          raise TermInvalidIcmpType('Term %s contains an invalid icmp-type:'
                                    '%s' % (self.name, icmptype))

  def AddressCleanup(self, optimize=True):
    """Do Address and Port collapsing.

    Notes:
      Collapses both the address definitions and the port definitions
      to their smallest possible length.

    Args:
      optimize: boolean value indicating whether to optimize addresses
    """
    if optimize:
      cleanup = nacaddr.CollapseAddrList
    else:
      cleanup = nacaddr.SortAddrList

    # address collapsing.
    if self.address:
      self.address = cleanup(self.address)
    if self.source_address:
      self.source_address = cleanup(self.source_address)
    if self.source_address_exclude:
      self.source_address_exclude = cleanup(self.source_address_exclude)
    if self.destination_address:
      self.destination_address = cleanup(self.destination_address)
    if self.destination_address_exclude:
      self.destination_address_exclude = cleanup(
          self.destination_address_exclude)

    # port collapsing.
    if self.port:
      self.port = self.CollapsePortList(self.port)
    if self.source_port:
      self.source_port = self.CollapsePortList(self.source_port)
    if self.destination_port:
      self.destination_port = self.CollapsePortList(self.destination_port)

  def CollapsePortListRecursive(self, ports):
    """Given a sorted list of ports, collapse to the smallest required list.

    Args:
      ports: sorted list of port tuples

    Returns:
      ret_ports: collapsed list of ports
    """
    optimized = False
    ret_ports = []
    for port in ports:
      if not ret_ports:
        ret_ports.append(port)
      # we should be able to count on ret_ports[-1][0] <= port[0]
      elif ret_ports[-1][1] >= port[1]:
        # (10, 20) and (12, 13) -> (10, 20)
        optimized = True
      elif port[0] < ret_ports[-1][1] < port[1]:
        # (10, 20) and (15, 30) -> (10, 30)
        ret_ports[-1] = (ret_ports[-1][0], port[1])
        optimized = True
      elif ret_ports[-1][1] + 1 == port[0]:
        # (10, 20) and (21, 30) -> (10, 30)
        ret_ports[-1] = (ret_ports[-1][0], port[1])
        optimized = True
      else:
        # (10, 20) and (22, 30) -> (10, 20), (22, 30)
        ret_ports.append(port)

    if optimized:
      return self.CollapsePortListRecursive(ret_ports)
    return ret_ports

  def CollapsePortList(self, ports):
    """Given a list of ports, Collapse to the smallest required.

    Args:
      ports: a list of port strings eg: [(80,80), (53,53) (2000, 2009),
                                         (1024,65535)]

    Returns:
      ret_array: the collapsed sorted list of ports, eg: [(53,53), (80,80),
                                                          (1024,65535)]
    """
    return self.CollapsePortListRecursive(sorted(ports))

  def CheckProtocolIsSuperset(self, superset, subset):
    """Check to if the given list of protocols is wholly contained.

    Args:
      superset: list of protocols
      subset: list of protocols

    Returns:
      bool: True if subset is contained in superset. false otherwise.
    """
    if not superset:
      return True
    if not subset:
      return False

    for sub_proto in subset:
      not_contains = True
      for sup_proto in superset:
        if sub_proto == sup_proto:
          not_contains = False
          break
      if not_contains:
        return False
    return True

  def CheckPortIsSuperset(self, superset, subset):
    """Check if the given list of ports is wholly contained.

    Args:
      superset: list of port tuples
      subset: list of port tuples

    Returns:
      bool: True if subset is contained in superset, false otherwise
    """
    if not superset:
      return True
    if not subset:
      return False

    for sub_port in subset:
      not_contains = True
      for sup_port in superset:
        if sub_port[0] >= sup_port[0] and sub_port[1] <= sup_port[1]:
          not_contains = False
          break
      if not_contains:
        return False
    return True

  def CheckAddressIsSuperset(self, superset, subset):
    """Check to see if subset is wholey contained by superset.

    Args:
      superset: list of the superset addresses
      subset: list of the subset addresses

    Returns:
      True or False.
    """
    if not superset:
      return True
    if not subset:
      return False

    for sub_addr in subset:
      not_contains = True
      for sup_addr in superset:
        if sub_addr in sup_addr and sub_addr.version == sup_addr.version:
          not_contains = False
          break
      if not_contains:
        return False
    return True


class VarType(object):
  """Generic object meant to store lots of basic policy types."""

  COMMENT = 0
  COUNTER = 1
  ACTION = 2
  SADDRESS = 3
  DADDRESS = 4
  ADDRESS = 5
  SPORT = 6
  DPORT = 7
  PROTOCOL_EXCEPT = 8
  OPTION = 9
  PROTOCOL = 10
  SADDREXCLUDE = 11
  DADDREXCLUDE = 12
  LOGGING = 13
  QOS = 14
  POLICER = 15
  PACKET_LEN = 16
  FRAGMENT_OFFSET = 17
  ICMP_TYPE = 18
  SPFX = 19
  DPFX = 20
  ETHER_TYPE = 21
  TRAFFIC_TYPE = 22
  VERBATIM = 23
  LOSS_PRIORITY = 24
  ROUTING_INSTANCE = 25
  PRECEDENCE = 26
  SINTERFACE = 27

  def __init__(self, var_type, value):
    self.var_type = var_type
    if self.var_type == self.COMMENT:
      # remove the double quotes
      comment = value.strip('"')
      # make all of the lines start w/o leading whitespace.
      self.value = '\n'.join(map(lambda x: x.lstrip(), comment.split('\n')))
    else:
      self.value = value

  def __str__(self):
    return self.value

  def __eq__(self, other):
    return self.var_type == other.var_type and self.value == other.value


class Header(object):
  """The header of the policy file contains the targets and a global comment."""

  def __init__(self):
    self.target = []
    self.comment = []

  def AddObject(self, obj):
    """Add and object to the Header.

    Args:
      obj: of type VarType.COMMENT or Target
    """
    if type(obj) == Target:
      self.target.append(obj)
    elif obj.var_type == VarType.COMMENT:
      self.comment.append(str(obj))

  @property
  def platforms(self):
    """The platform targets of this particular header."""
    return map(lambda x: x.platform, self.target)

  def FilterOptions(self, platform):
    """Given a platform return the options.

    Args:
      platform: string

    Returns:
      list or None
    """
    for target in self.target:
      if target.platform == platform:
        return target.options
    return []

  def FilterName(self, platform):
    """Given a filter_type, return the filter name.

    Args:
      platform: string

    Returns:
      filter_name: string or None

    Notes:
      !! Deprecated in favor of Header.FilterOptions(platform) !!
    """
    for target in self.target:
      if target.platform == platform:
        if target.options:
          return target.options[0]
    return None


# This could be a VarType object, but I'm keeping it as it's class
# b/c we're almost certainly going to have to do something more exotic with
# it shortly to account for various rendering options like default iptables
# policies or output file names, etc. etc.
class Target(object):
  """The type of acl to be rendered from this policy file."""

  def __init__(self, target):
    self.platform = target[0]
    if len(target) > 1:
      self.options = target[1:]
    else:
      self.options = None

  def __str__(self):
    return self.platform

  def __eq__(self, other):
    return self.platform == other.platform and self.options == other.options

  def __ne__(self, other):
    return not self.__eq__(other)


# Lexing/Parsing starts here
tokens = (
    'ACTION',
    'ADDR',
    'COMMENT',
    'COUNTER',
    'DADDR',
    'DADDREXCLUDE',
    'DPFX',
    'DPORT',
    'DQUOTEDSTRING',
    'ETHER_TYPE',
    'FRAGMENT_OFFSET',
    'HEADER',
    'ICMP_TYPE',
    'INTEGER',
    'LOGGING',
    'LOSS_PRIORITY',
    'OPTION',
    'PROTOCOL',
    'PROTOCOL_EXCEPT',
    'PACKET_LEN',
    'POLICER',
    'PRECEDENCE',
    'QOS',
    'ROUTING_INSTANCE',
    'SADDR',
    'SADDREXCLUDE',
    'SINTERFACE',
    'SPFX',
    'SPORT',
    'STRING',
    'TARGET',
    'TERM',
    'TRAFFIC_TYPE',
    'VERBATIM',
)

literals = r':{},-'
t_ignore = ' \t'

reserved = {
    'action': 'ACTION',
    'address': 'ADDR',
    'comment': 'COMMENT',
    'counter': 'COUNTER',
    'destination-address': 'DADDR',
    'destination-exclude': 'DADDREXCLUDE',
    'destination-prefix': 'DPFX',
    'destination-port': 'DPORT',
    'ether-type': 'ETHER_TYPE',
    'fragment-offset': 'FRAGMENT_OFFSET',
    'header': 'HEADER',
    'icmp-type': 'ICMP_TYPE',
    'logging': 'LOGGING',
    'loss-priority': 'LOSS_PRIORITY',
    'option': 'OPTION',
    'packet-length': 'PACKET_LEN',
    'policer': 'POLICER',
    'precedence': 'PRECEDENCE',
    'protocol': 'PROTOCOL',
    'protocol-except': 'PROTOCOL_EXCEPT',
    'qos': 'QOS',
    'routing-instance': 'ROUTING_INSTANCE',
    'source-address': 'SADDR',
    'source-exclude': 'SADDREXCLUDE',
    'source-interface': 'SINTERFACE',
    'source-prefix': 'SPFX',
    'source-port': 'SPORT',
    'target': 'TARGET',
    'term': 'TERM',
    'traffic-type': 'TRAFFIC_TYPE',
    'verbatim': 'VERBATIM',
}


# disable linting warnings for lexx/yacc code
# pylint: disable-msg=W0613,C6102,C6104,C6105,C6108,C6409


def t_IGNORE_COMMENT(t):
  r'\#.*'
  pass


def t_DQUOTEDSTRING(t):
  r'"[^"]*?"'
  t.lexer.lineno += str(t.value).count('\n')
  return t


def t_newline(t):
  r'\n+'
  t.lexer.lineno += len(t.value)


def t_error(t):
  print "Illegal character '%s' on line %s" % (t.value[0], t.lineno)
  t.lexer.skip(1)


def t_INTEGER(t):
  r'\d+'
  return t


def t_STRING(t):
  r'\w+([-_+]\w*)*'
  # we have an identifier; let's check if it's a keyword or just a string.
  t.type = reserved.get(t.value, 'STRING')
  return t


###
## parser starts here
###
def p_target(p):
  """ target : target header terms
             | """
  if len(p) > 1:
    if type(p[1]) is Policy:
      p[1].AddFilter(p[2], p[3])
      p[0] = p[1]
    else:
      p[0] = Policy(p[2], p[3])


def p_header(p):
  """ header : HEADER '{' header_spec '}' """
  p[0] = p[3]


def p_header_spec(p):
  """ header_spec : header_spec target_spec
                  | header_spec comment_spec
                  | """
  if len(p) > 1:
    if type(p[1]) == Header:
      p[1].AddObject(p[2])
      p[0] = p[1]
    else:
      p[0] = Header()
      p[0].AddObject(p[2])


# we may want to change this at some point if we want to be clever with things
# like being able to set a default input/output policy for iptables policies.
def p_target_spec(p):
  """ target_spec : TARGET ':' ':' strings_or_ints """
  p[0] = Target(p[4])


def p_terms(p):
  """ terms : terms TERM STRING '{' term_spec '}'
            | """
  if len(p) > 1:
    p[5].name = p[3]
    if type(p[1]) == list:
      p[1].append(p[5])
      p[0] = p[1]
    else:
      p[0] = [p[5]]


def p_term_spec(p):
  """ term_spec : term_spec action_spec
                | term_spec addr_spec
                | term_spec comment_spec
                | term_spec counter_spec
                | term_spec ether_type_spec
                | term_spec exclude_spec
                | term_spec fragment_offset_spec
                | term_spec icmp_type_spec
                | term_spec interface_spec
                | term_spec logging_spec
                | term_spec losspriority_spec
                | term_spec option_spec
                | term_spec packet_length_spec
                | term_spec policer_spec
                | term_spec port_spec
                | term_spec precedence_spec
                | term_spec prefix_list_spec
                | term_spec protocol_spec
                | term_spec qos_spec
                | term_spec routinginstance_spec
                | term_spec traffic_type_spec
                | term_spec verbatim_spec
                | """
  if len(p) > 1:
    if type(p[1]) == Term:
      p[1].AddObject(p[2])
      p[0] = p[1]
    else:
      p[0] = Term(p[2])


def p_routinginstance_spec(p):
  """ routinginstance_spec : ROUTING_INSTANCE ':' ':' STRING """
  p[0] = VarType(VarType.ROUTING_INSTANCE, p[4])


def p_losspriority_spec(p):
  """ losspriority_spec :  LOSS_PRIORITY ':' ':' STRING """
  p[0] = VarType(VarType.LOSS_PRIORITY, p[4])


def p_precedence_spec(p):
  """ precedence_spec : PRECEDENCE ':' ':' INTEGER """
  p[0] = VarType(VarType.PRECEDENCE, p[4])


def p_icmp_type_spec(p):
  """ icmp_type_spec : ICMP_TYPE ':' ':' one_or_more_strings """
  p[0] = VarType(VarType.ICMP_TYPE, p[4])


def p_packet_length_spec(p):
  """ packet_length_spec : PACKET_LEN ':' ':' INTEGER
                         | PACKET_LEN ':' ':' INTEGER '-' INTEGER """
  if len(p) == 4:
    p[0] = VarType(VarType.PACKET_LEN, str(p[4]))
  else:
    p[0] = VarType(VarType.PACKET_LEN, str(p[4]) + '-' + str(p[6]))


def p_fragment_offset_spec(p):
  """ fragment_offset_spec : FRAGMENT_OFFSET ':' ':' INTEGER
                           | FRAGMENT_OFFSET ':' ':' INTEGER '-' INTEGER """
  if len(p) == 4:
    p[0] = VarType(VarType.FRAGMENT_OFFSET, str(p[4]))
  else:
    p[0] = VarType(VarType.FRAGMENT_OFFSET, str(p[4]) + '-' + str(p[6]))


def p_exclude_spec(p):
  """ exclude_spec : SADDREXCLUDE ':' ':' one_or_more_strings
                   | DADDREXCLUDE ':' ':' one_or_more_strings
                   | PROTOCOL_EXCEPT ':' ':' one_or_more_strings """

  p[0] = []
  for ex in p[4]:
    if p[1].find('source-exclude') >= 0:
      p[0].append(VarType(VarType.SADDREXCLUDE, ex))
    elif p[1].find('destination-exclude') >= 0:
      p[0].append(VarType(VarType.DADDREXCLUDE, ex))
    elif p[1].find('protocol-except') >= 0:
      p[0].append(VarType(VarType.PROTOCOL_EXCEPT, ex))


def p_prefix_list_spec(p):
  """ prefix_list_spec : DPFX ':' ':' one_or_more_strings
                       | SPFX ':' ':' one_or_more_strings """
  p[0] = []
  for pfx in p[4]:
    if p[1].find('source-prefix') >= 0:
      p[0].append(VarType(VarType.SPFX, pfx))
    elif p[1].find('destination-prefix') >= 0:
      p[0].append(VarType(VarType.DPFX, pfx))


def p_addr_spec(p):
  """ addr_spec : SADDR ':' ':' one_or_more_strings
                | DADDR ':' ':' one_or_more_strings
                | ADDR  ':' ':' one_or_more_strings """
  p[0] = []
  for addr in p[4]:
    if p[1].find('source-address') >= 0:
      p[0].append(VarType(VarType.SADDRESS, addr))
    elif p[1].find('destination-address') >= 0:
      p[0].append(VarType(VarType.DADDRESS, addr))
    else:
      p[0].append(VarType(VarType.ADDRESS, addr))


def p_port_spec(p):
  """ port_spec : SPORT ':' ':' one_or_more_strings
                | DPORT ':' ':' one_or_more_strings """
  p[0] = []
  for port in p[4]:
    if p[1].find('source-port') >= 0:
      p[0].append(VarType(VarType.SPORT, port))
    else:
      p[0].append(VarType(VarType.DPORT, port))


def p_protocol_spec(p):
  """ protocol_spec : PROTOCOL ':' ':' strings_or_ints """
  p[0] = []
  for proto in p[4]:
    p[0].append(VarType(VarType.PROTOCOL, proto))


def p_ether_type_spec(p):
  """ ether_type_spec : ETHER_TYPE ':' ':' one_or_more_strings """
  p[0] = []
  for proto in p[4]:
    p[0].append(VarType(VarType.ETHER_TYPE, proto))


def p_traffic_type_spec(p):
  """ traffic_type_spec : TRAFFIC_TYPE ':' ':' one_or_more_strings """
  p[0] = []
  for proto in p[4]:
    p[0].append(VarType(VarType.TRAFFIC_TYPE, proto))


def p_policer_spec(p):
  """ policer_spec : POLICER ':' ':' STRING """
  p[0] = VarType(VarType.POLICER, p[4])


def p_logging_spec(p):
  """ logging_spec : LOGGING ':' ':' STRING """
  p[0] = VarType(VarType.LOGGING, p[4])


def p_option_spec(p):
  """ option_spec : OPTION ':' ':' one_or_more_strings """
  p[0] = []
  for opt in p[4]:
    p[0].append(VarType(VarType.OPTION, opt))


def p_action_spec(p):
  """ action_spec : ACTION ':' ':' STRING """
  p[0] = VarType(VarType.ACTION, p[4])


def p_counter_spec(p):
  """ counter_spec : COUNTER ':' ':' STRING """
  p[0] = VarType(VarType.COUNTER, p[4])


def p_comment_spec(p):
  """ comment_spec : COMMENT ':' ':' DQUOTEDSTRING """
  p[0] = VarType(VarType.COMMENT, p[4])


def p_verbatim_spec(p):
  """ verbatim_spec : VERBATIM ':' ':' STRING DQUOTEDSTRING """
  p[0] = VarType(VarType.VERBATIM, [p[4], p[5].strip('"')])


def p_qos_spec(p):
  """ qos_spec : QOS ':' ':' STRING """
  p[0] = VarType(VarType.QOS, p[4])


def p_interface_spec(p):
  """ interface_spec : SINTERFACE ':' ':' STRING """
  p[0] = VarType(VarType.SINTERFACE, p[4])


def p_one_or_more_strings(p):
  """ one_or_more_strings : one_or_more_strings STRING
                          | STRING
                          | """
  if len(p) > 1:
    if type(p[1]) == type([]):
      p[1].append(p[2])
      p[0] = p[1]
    else:
      p[0] = [p[1]]


def p_strings_or_ints(p):
  """ strings_or_ints : strings_or_ints STRING
                      | strings_or_ints INTEGER
                      | STRING
                      | INTEGER
                      | """
  if len(p) > 1:
    if type(p[1]) is list:
      p[1].append(p[2])
      p[0] = p[1]
    else:
      p[0] = [p[1]]


def p_error(p):
  """."""
  next_token = yacc.token()
  if next_token is None:
    use_token = 'EOF'
  else:
    use_token = repr(next_token.value)

  if p:
    raise ParseError(' ERROR on "%s" (type %s, line %d, Next %s)'
                     % (p.value, p.type, p.lineno, use_token))
  else:
    raise ParseError(' ERROR you likely have unablanaced "{"\'s')

# pylint: enable-msg=W0613,C6102,C6104,C6105,C6108,C6409


def _ReadFile(filename):
  """Read data from a file if it exists.

  Args:
    filename: str - Filename

  Returns:
    data: str contents of file.

  Raises:
    FileNotFoundError: if requested file does not exist.
    FileReadError: Any error resulting from trying to open/read file.
  """
  if os.path.exists(filename):
    try:
      data = open(filename, 'r').read()
      return data
    except IOError:
      raise FileReadError('Unable to open or read file %s' % filename)
  else:
    raise FileNotFoundError('Unable to open policy file %s' % filename)


def _Preprocess(data, max_depth=5, base_dir=''):
  """Search input for include statements and import specified include file.

  Search input for include statements and if found, import specified file
  and recursively search included data for includes as well up to max_depth.

  Args:
    data: A string of Policy file data.
    max_depth: Maximum depth of included files
    base_dir: Base path string where to look for policy or include files

  Returns:
    A string containing result of the processed input data

  Raises:
    RecursionTooDeepError: nested include files exceed maximum
  """
  if not max_depth:
    raise RecursionTooDeepError('%s' % (
        'Included files exceed maximum recursion depth of %s.' % max_depth))
  rval = []
  lines = [x.rstrip() for x in data.splitlines()]
  for line in lines:
    words = line.split()
    if len(words) > 1 and words[0] == '#include':
      # remove any quotes around included filename
      include_file = words[1].strip('\'"')
      data = _ReadFile(os.path.join(base_dir, include_file))
      # recursively handle includes in included data
      inc_data = _Preprocess(data, max_depth - 1, base_dir=base_dir)
      rval.extend(inc_data)
    else:
      rval.append(line)
  return rval


def ParseFile(filename, definitions=None, optimize=True, base_dir=''):
  """Parse the policy contained in file, optionally provide a naming object.

  Read specified policy file and parse into a policy object.

  Args:
    filename: Name of policy file to parse.
    definitions: optional naming library definitions object.
    optimize: bool - whether to summarize networks and services.
    base_dir: base path string to look for acls or include files.

  Returns:
    policy object.
  """
  data = _ReadFile(filename)
  p = ParsePolicy(data, definitions, optimize, base_dir=base_dir)
  return p


def ParsePolicy(data, definitions=None, optimize=True, base_dir=''):
  """Parse the policy in 'data', optionally provide a naming object.

  Parse a blob of policy text into a policy object.

  Args:
    data: a string blob of policy data to parse.
    definitions: optional naming library definitions object.
    optimize: bool - whether to summarize networks and services.
    base_dir: base path string to look for acls or include files.

  Returns:
    policy object.
  """
  try:
    if definitions:
      globals()['DEFINITIONS'] = definitions
    else:
      globals()['DEFINITIONS'] = naming.Naming(DEFAULT_DEFINITIONS)
    if not optimize:
      globals()['_OPTIMIZE'] = False

    # I wanna lex you up
    lexer = lex.lex()

    preprocessed_data = '\n'.join(_Preprocess(data, base_dir=base_dir))

    p = yacc.yacc(write_tables=False, debug=0, errorlog=yacc.NullLogger())

    return p.parse(preprocessed_data, lexer=lexer)

  except IndexError:
    return False


# if you call this from the command line, you can specify a jcl file for it to
# read.
if __name__ == '__main__':
  ret = 0
  if len(sys.argv) > 1:
    try:
      ret = ParsePolicy(open(sys.argv[1], 'r').read())
    except IOError:
      print('ERROR: \'%s\' either does not exist or is not readable' %
            (sys.argv[1]))
      ret = 1
  else:
    # default to reading stdin
    ret = ParsePolicy(sys.stdin.read())
  sys.exit(ret)
