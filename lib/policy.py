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

import datetime
from functools import wraps
import os
import sys

import logging
import nacaddr
import naming

from third_party.ply import lex
from third_party.ply import yacc


DEFINITIONS = None
DEFAULT_DEFINITIONS = './def'
_ACTIONS = set(('accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'))
_LOGGING = set(('true', 'True', 'syslog', 'local', 'disable'))
_OPTIMIZE = True
_SHADE_CHECK = False


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


class HeaderDuplicateTargetPlatformError(Error):
  """Same target platform added to Header, resulting in ambiguity for options."""


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


class ShadingError(Error):
  """Error when a term is shaded by a prior term."""


def TranslatePorts(ports, protocols, term_name):
  """Return all ports of all protocols requested.

  Args:
    ports: list of ports, eg ['SMTP', 'DNS', 'HIGH_PORTS']
    protocols: list of protocols, eg ['tcp', 'udp']
    term_name: name of current term, used for warning messages

  Returns:
    ret_array: list of ports tuples such as [(25,25), (53,53), (1024,65535)]

  Note:
    Duplication will be taken care of in Term.CollapsePortList
  """
  ret_array = []
  for proto in protocols:
    for port in ports:
      service_by_proto = DEFINITIONS.GetServiceByProto(port, proto)
      if not service_by_proto:
        logging.warn('%s %s %s %s %s %s%s %s', 'Term', term_name,
                     'has service', port, 'which is not defined with protocol',
                     proto,
                     ', but will be permitted. Unless intended, you should',
                     'consider splitting the protocols into separate terms!')

      for p in [x.split('-') for x in service_by_proto]:
        if len(p) == 1:
          ret_array.append((int(p[0]), int(p[0])))
        else:
          ret_array.append((int(p[0]), int(p[1])))
  return ret_array


# classes for storing the object types in the policy files.
class Policy(object):
  """The policy object contains everything found in a given policy file."""

  def __init__(self, header, terms):
    """Initiator for the Policy object.

    Args:
      header: __main__.Header object. contains comments which should be passed
        on to the rendered acls as well as the type of acls this policy file
        should render to.

      terms: list __main__.Term. an array of Term objects which must be rendered
        in each of the rendered acls.

    Attributes:
      filters: list of tuples containing (header, terms).
    """
    self.filters = []
    self.AddFilter(header, terms)

  def AddFilter(self, header, terms):
    """Add another header & filter."""
    self.filters.append((header, terms))
    self._TranslateTerms(terms)
    if _SHADE_CHECK:
      self._DetectShading(terms)

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
        term.port = TranslatePorts(term.port, term.protocol, term.name)
        if not term.port:
          raise TermPortProtocolError(
              'no ports of the correct protocol for term %s' % (
                  term.name))
      if term.source_port:
        term.source_port = TranslatePorts(term.source_port, term.protocol,
                                          term.name)
        if not term.source_port:
          raise TermPortProtocolError(
              'no source ports of the correct protocol for term %s' % (
                  term.name))
      if term.destination_port:
        term.destination_port = TranslatePorts(term.destination_port,
                                               term.protocol, term.name)
        if not term.destination_port:
          raise TermPortProtocolError(
              'no destination ports of the correct protocol for term %s' % (
                  term.name))

      # If argument is true, we optimize, otherwise just sort addresses
      term.AddressCleanup(_OPTIMIZE)
      # Reset _OPTIMIZE global to default value
      globals()['_OPTIMIZE'] = True
      term.SanityCheck()
      term.translated = True

  @property
  def headers(self):
    """Returns the headers from each of the configured filters.

    Returns:
      headers
    """
    return [x[0] for x in self.filters]

  def _DetectShading(self, terms):
    """Finds terms which are shaded (impossible to reach).

    Iterate through each term, looking at each prior term. If a prior term
    contains every component of the current term then the current term would
    never be hit and is thus shaded. This can be a mistake.

    Args:
      terms: list of Term objects.

    Raises:
      ShadingError: When a term is impossible to reach.
    """
    # Reset _OPTIMIZE global to default value
    globals()['_SHADE_CHECK'] = False
    shading_errors = []
    for index, term in enumerate(terms):
      for prior_index in xrange(index):
        # Check each term that came before for shading. Terms with next as an
        # action do not terminate evaluation, so cannot shade.
        if (term in terms[prior_index]
            and 'next' not in terms[prior_index].action):
          shading_errors.append(
              '  %s is shaded by %s.' % (
                  term.name, terms[prior_index].name))
    if shading_errors:
      raise ShadingError('\n'.join(shading_errors))


class Term(object):
  """The Term object is used to store each of the terms.

  Args:
    obj: an object of type VarType or a list of objects of type VarType

  members:
    address/source_address/destination_address/: list of
      VarType.(S|D)?ADDRESS's
    address_exclude/source_address_exclude/destination_address_exclude: list of
      VarType.(S|D)?ADDEXCLUDE's
    port/source_port/destination_port: list of VarType.(S|D)?PORT's
    options: list of VarType.OPTION's.
    protocol: list of VarType.PROTOCOL's.
    counter: VarType.COUNTER
    action: list of VarType.ACTION's
    comments: VarType.COMMENT
    expiration: VarType.EXPIRATION
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
    self.address_exclude = []
    self.comment = []
    self.counter = None
    self.expiration = None
    self.destination_address = []
    self.destination_address_exclude = []
    self.destination_port = []
    self.destination_prefix = []
    self.logging = []
    self.loss_priority = None
    self.option = []
    self.owner = None
    self.policer = None
    self.port = []
    self.precedence = []
    self.principals = []
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
    # gce specific
    self.source_tag = []
    self.destination_tag = []
    # iptables specific
    self.source_interface = None
    self.destination_interface = None
    self.platform = []
    self.platform_exclude = []
    self.timeout = None
    self.flattened = False
    self.flattened_addr = None
    self.flattened_saddr = None
    self.flattened_daddr = None

    # AddObject touches variables which might not have been initialized
    # further up so this has to be at the end.
    self.AddObject(obj)

  def __contains__(self, other):
    """Determine if other term is contained in this term."""
    if self.verbatim or other.verbatim:
      # short circuit these
      if sorted(self.verbatim) != sorted(other.verbatim):
        return False

    # check prototols
    # either protocol or protocol-except may be used, not both at the same time.
    if self.protocol:
      if other.protocol:
        if not self.CheckProtocolIsContained(other.protocol, self.protocol):
          return False
      # this term has protocol, other has protocol_except.
      elif other.protocol_except:
        return False
      else:
        # other does not have protocol or protocol_except. since we do other
        # cannot be contained in self.
        return False
    elif self.protocol_except:
      if other.protocol_except:
        if self.CheckProtocolIsContained(
            self.protocol_except, other.protocol_except):
          return False
      elif other.protocol:
        for proto in other.protocol:
          if proto in self.protocol_except:
            return False
      else:
        return False

    # combine addresses with exclusions for proper contains comparisons.
    if not self.flattened:
      self.FlattenAll()
    if not other.flattened:
      other.FlattenAll()

    # flat 'address' is compared against other flat (saddr|daddr).
    # if NONE of these evaluate to True other is not contained.
    if not (
        self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_addr)
        or self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_saddr)
        or self.CheckAddressIsContained(
            self.flattened_addr, other.flattened_daddr)):
      return False

    # compare flat address from other to flattened self (saddr|daddr).
    if not (
        # other's flat address needs both self saddr & daddr to contain in order
        # for the term to be contained. We already compared the flattened_addr
        # attributes of both above, which was not contained.
        self.CheckAddressIsContained(
            other.flattened_addr, self.flattened_saddr)
        and self.CheckAddressIsContained(
            other.flattened_addr, self.flattened_daddr)):
      return False

    # basic saddr/daddr check.
    if not (
        self.CheckAddressIsContained(
            self.flattened_saddr, other.flattened_saddr)):
      return False
    if not (
        self.CheckAddressIsContained(
            self.flattened_daddr, other.flattened_daddr)):
      return False

    if not (
        self.CheckPrincipalsContained(
            self.principals, other.principals)):
      return False

    # check ports
    # like the address directive, the port directive is special in that it can
    # be either source or destination.
    if self.port:
      if not (self.CheckPortIsContained(self.port, other.port) or
              self.CheckPortIsContained(self.port, other.sport) or
              self.CheckPortIsContained(self.port, other.dport)):
        return False
    if not self.CheckPortIsContained(self.source_port, other.source_port):
      return False
    if not self.CheckPortIsContained(self.destination_port,
                                     other.destination_port):
      return False

    # prefix lists
    if self.source_prefix:
      if sorted(self.source_prefix) != sorted(other.source_prefix):
        return False
    if self.destination_prefix:
      if sorted(self.destination_prefix) != sorted(
          other.destination_prefix):
        return False

    # check source and destination tags
    if self.source_tag:
      if sorted(self.source_tag != sorted(other.source_tag)):
        return False
      if sorted(self.destination_tag != sorted(other.destination_tag)):
        return False

    # check precedence
    if self.precedence:
      if not other.precedence:
        return False
      for precedence in other.precedence:
        if precedence not in self.precedence:
          return False
    # check various options
    if self.option:
      if not other.option:
        return False
      for opt in other.option:
        if opt not in self.option:
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

    # check platform
    if self.platform:
      if sorted(self.platform) is not sorted(other.platform):
        return False
    if self.platform_exclude:
      if sorted(self.platform_exclude) is not sorted(other.platform_exclude):
        return False

    # we have containment
    return True

  def __str__(self):
    ret_str = []
    ret_str.append(' name: %s' % self.name)
    if self.address:
      ret_str.append('  address: %s' % self.address)
    if self.address_exclude:
      ret_str.append('  address_exclude: %s' % self.address_exclude)
    if self.source_address:
      ret_str.append('  source_address: %s' % self.source_address)
    if self.source_address_exclude:
      ret_str.append('  source_address_exclude: %s' %
                     self.source_address_exclude)
    if self.source_tag:
      ret_str.append('  source_tag: %s' % self.source_tag)
    if self.destination_address:
      ret_str.append('  destination_address: %s' % self.destination_address)
    if self.destination_address_exclude:
      ret_str.append('  destination_address_exclude: %s' %
                     self.destination_address_exclude)
    if self.destination_tag:
      ret_str.append('  destination_tag: %s' % self.destination_tag)
    if self.source_prefix:
      ret_str.append('  source_prefix: %s' % self.source_prefix)
    if self.destination_prefix:
      ret_str.append('  destination_prefix: %s' % self.destination_prefix)
    if self.protocol:
      ret_str.append('  protocol: %s' % self.protocol)
    if self.protocol_except:
      ret_str.append('  protocol-except: %s' % self.protocol_except)
    if self.owner:
      ret_str.append('  owner: %s' % self.owner)
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
    if self.destination_interface:
      ret_str.append('  destination_interface: %s' % self.destination_interface)
    if self.expiration:
      ret_str.append('  expiration: %s' % self.expiration)
    if self.platform:
      ret_str.append('  platform: %s' % self.platform)
    if self.platform_exclude:
      ret_str.append('  platform_exclude: %s' % self.platform_exclude)
    if self.timeout:
      ret_str.append('  timeout: %s' % self.timeout)
    return '\n'.join(ret_str)

  def __eq__(self, other):
    # action
    if sorted(self.action) != sorted(other.action):
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
    if sorted(self.option) != sorted(other.option):
      return False

    # qos
    if self.qos != other.qos:
      return False

    # verbatim
    if self.verbatim != other.verbatim:
      return False

    # policer
    if self.policer != other.policer:
      return False

    # interface
    if self.source_interface != other.source_interface:
      return False

    if self.destination_interface != other.destination_interface:
      return False

    # tags
    if not (sorted(self.source_tag) == sorted(other.source_tag) and
            sorted(self.destination_tag) == sorted(other.destination_tag)):
      return False

    if sorted(self.logging) != sorted(other.logging):
      return False
    if self.qos != other.qos:
      return False
    if self.packet_length != other.packet_length:
      return False
    if self.fragment_offset != other.fragment_offset:
      return False
    if sorted(self.icmp_type) != sorted(other.icmp_type):
      return False
    if sorted(self.ether_type) != sorted(other.ether_type):
      return False
    if sorted(self.traffic_type) != sorted(other.traffic_type):
      return False

    # platform
    if not (sorted(self.platform) == sorted(other.platform) and
            sorted(self.platform_exclude) == sorted(other.platform_exclude)):
      return False

    # timeout
    if self.timeout != other.timeout:
      return False

    return True

  def __ne__(self, other):
    return not self.__eq__(other)

  def FlattenAll(self):
    """Reduce source, dest, and address fields to their post-exclude state.

    Populates the self.flattened_addr, self.flattened_saddr,
    self.flattened_daddr by removing excludes from includes.
    """
    # No excludes, set flattened attributes and move along.
    self.flattened = True
    if not (self.source_address_exclude or self.destination_address_exclude or
            self.address_exclude):
      self.flattened_saddr = self.source_address
      self.flattened_daddr = self.destination_address
      self.flattened_addr = self.address
      return

    if self.source_address_exclude:
      self.flattened_saddr = self._FlattenAddresses(
          self.source_address, self.source_address_exclude)
    if self.destination_address_exclude:
      self.flattened_daddr = self._FlattenAddresses(
          self.destination_address, self.destination_address_exclude)
    if self.address_exclude:
      self.flattened_addr = self._FlattenAddresses(
          self.address, self.address_exclude)


  @staticmethod
  def _FlattenAddresses(include, exclude):
    """Reduce an include and exclude list to a single include list.

    Using recursion, whittle away exclude addresses from address include
    addresses which contain the exclusion.

    Args:
      include: list of include addresses.
      exclude: list of exclude addresses.
    Returns:
      a single flattened list of nacaddr objects.
    """
    if not exclude:
      return include

    for index, in_addr in enumerate(include):
      for ex_addr in exclude:
        if ex_addr in in_addr:
          reduced_list = in_addr.address_exclude(ex_addr)
          include.pop(index)
          include.extend(
              Term._FlattenAddresses(reduced_list, exclude[1:]))
    return include

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
        [Address, Port, Option, Protocol, Counter, Action, Comment, Expiration]

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
        # expanded address fields consolidate naked address fields with
        # saddr/daddr.
        if x.var_type is VarType.SADDRESS:
          saddr = DEFINITIONS.GetNetAddr(x.value)
          self.source_address.extend(saddr)
        elif x.var_type is VarType.DADDRESS:
          daddr = DEFINITIONS.GetNetAddr(x.value)
          self.destination_address.extend(daddr)
        elif x.var_type is VarType.ADDRESS:
          addr = DEFINITIONS.GetNetAddr(x.value)
          self.address.extend(addr)
        # do we have address excludes?
        elif x.var_type is VarType.SADDREXCLUDE:
          saddr_exclude = DEFINITIONS.GetNetAddr(x.value)
          self.source_address_exclude.extend(saddr_exclude)
        elif x.var_type is VarType.DADDREXCLUDE:
          daddr_exclude = DEFINITIONS.GetNetAddr(x.value)
          self.destination_address_exclude.extend(daddr_exclude)
        elif x.var_type is VarType.ADDREXCLUDE:
          addr_exclude = DEFINITIONS.GetNetAddr(x.value)
          self.address_exclude.extend(addr_exclude)
        # do we have a list of ports?
        elif x.var_type is VarType.PORT:
          self.port.append(x.value)
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
        elif x.var_type is VarType.PRINCIPALS:
          self.principals.append(x.value)
        elif x.var_type is VarType.SPFX:
          self.source_prefix.append(x.value)
        elif x.var_type is VarType.DPFX:
          self.destination_prefix.append(x.value)
        elif x.var_type is VarType.ETHER_TYPE:
          self.ether_type.append(x.value)
        elif x.var_type is VarType.TRAFFIC_TYPE:
          self.traffic_type.append(x.value)
        elif x.var_type is VarType.PRECEDENCE:
          self.precedence.append(x.value)
        elif x.var_type is VarType.PLATFORM:
          self.platform.append(x.value)
        elif x.var_type is VarType.PLATFORMEXCLUDE:
          self.platform_exclude.append(x.value)
        elif x.var_type is VarType.STAG:
          self.source_tag.append(x.value)
        elif x.var_type is VarType.DTAG:
          self.destination_tag.append(x.value)
        else:
          raise TermObjectTypeError(
              '%s isn\'t a type I know how to deal with (contains \'%s\')' % (
                  type(x), x.value))
    else:
      # stupid no switch statement in python
      if obj.var_type is VarType.COMMENT:
        self.comment.append(str(obj))
      elif obj.var_type is VarType.OWNER:
        self.owner = obj.value
      elif obj.var_type is VarType.EXPIRATION:
        self.expiration = obj.value
      elif obj.var_type is VarType.LOSS_PRIORITY:
        self.loss_priority = obj.value
      elif obj.var_type is VarType.ROUTING_INSTANCE:
        self.routing_instance = obj.value
      elif obj.var_type is VarType.PRECEDENCE:
        self.precedence = obj.value
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
      elif obj.var_type is VarType.DINTERFACE:
        self.destination_interface = obj.value
      elif obj.var_type is VarType.TIMEOUT:
        self.timeout = obj.value
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

  def CheckPrincipalsContained(self, superset, subset):
    """Check to if the given list of principals is wholly contained.

    Args:
      superset: list of principals
      subset: list of principals

    Returns:
      bool: True if subset is contained in superset. false otherwise.
    """
    # Skip set comparison if neither term has principals.
    if not superset and not subset:
      return True

    # Convert these lists to sets to use set comparison.
    sup = set(superset)
    sub = set(subset)
    return sub.issubset(sup)

  def CheckProtocolIsContained(self, superset, subset):
    """Check if the given list of protocols is wholly contained.

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

    # Convert these lists to sets to use set comparison.
    sup = set(superset)
    sub = set(subset)
    return sub.issubset(sup)

  def CheckPortIsContained(self, superset, subset):
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
        if (int(sub_port[0]) >= int(sup_port[0])
            and int(sub_port[1]) <= int(sup_port[1])):
          not_contains = False
          break
      if not_contains:
        return False
    return True

  def CheckAddressIsContained(self, superset, subset):
    """Check if subset is wholey contained by superset.

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
      sub_contained = False
      for sup_addr in superset:
        # ipaddr ensures that version numbers match for inclusion.
        if sub_addr in sup_addr:
          sub_contained = True
          break
      if not sub_contained:
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
  EXPIRATION = 28
  DINTERFACE = 29
  PLATFORM = 30
  PLATFORMEXCLUDE = 31
  PORT = 32
  TIMEOUT = 33
  OWNER = 34
  PRINCIPALS = 35
  ADDREXCLUDE = 36
  STAG = 44
  DTAG = 45

  def __init__(self, var_type, value):
    self.var_type = var_type
    if self.var_type == self.COMMENT:
      # remove the double quotes
      comment = value.strip('"')
      # make all of the lines start w/o leading whitespace.
      self.value = '\n'.join([x.lstrip() for x in comment.splitlines()])
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

    Raises:
      HeaderDuplicateTargetPlatformError: When the same platform is added as a target.
    """
    if type(obj) == Target:
      if obj.platform in self.platforms:
        raise HeaderDuplicateTargetPlatformError('duplicate platform {0}'.format(obj.platform))
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
    'ADDREXCLUDE',
    'COMMENT',
    'COUNTER',
    'DADDR',
    'DADDREXCLUDE',
    'DPFX',
    'DPORT',
    'DINTERFACE',
    'DQUOTEDSTRING',
    'DTAG',
    'ETHER_TYPE',
    'EXPIRATION',
    'FRAGMENT_OFFSET',
    'HEADER',
    'ICMP_TYPE',
    'INTEGER',
    'LOGGING',
    'LOSS_PRIORITY',
    'OPTION',
    'OWNER',
    'PACKET_LEN',
    'PLATFORM',
    'PLATFORMEXCLUDE',
    'POLICER',
    'PORT',
    'PRECEDENCE',
    'PRINCIPALS',
    'PROTOCOL',
    'PROTOCOL_EXCEPT',
    'QOS',
    'ROUTING_INSTANCE',
    'SADDR',
    'SADDREXCLUDE',
    'SINTERFACE',
    'SPFX',
    'SPORT',
    'STAG',
    'STRING',
    'TARGET',
    'TERM',
    'TIMEOUT',
    'TRAFFIC_TYPE',
    'VERBATIM',
)

literals = r':{},-'
t_ignore = ' \t'

reserved = {
    'action': 'ACTION',
    'address': 'ADDR',
    'address-exclude': 'ADDREXCLUDE',
    'comment': 'COMMENT',
    'counter': 'COUNTER',
    'destination-address': 'DADDR',
    'destination-exclude': 'DADDREXCLUDE',
    'destination-interface': 'DINTERFACE',
    'destination-prefix': 'DPFX',
    'destination-port': 'DPORT',
    'destination-tag': 'DTAG',
    'ether-type': 'ETHER_TYPE',
    'expiration': 'EXPIRATION',
    'fragment-offset': 'FRAGMENT_OFFSET',
    'header': 'HEADER',
    'icmp-type': 'ICMP_TYPE',
    'logging': 'LOGGING',
    'loss-priority': 'LOSS_PRIORITY',
    'option': 'OPTION',
    'owner': 'OWNER',
    'packet-length': 'PACKET_LEN',
    'platform': 'PLATFORM',
    'platform-exclude': 'PLATFORMEXCLUDE',
    'policer': 'POLICER',
    'port': 'PORT',
    'precedence': 'PRECEDENCE',
    'principals': 'PRINCIPALS',
    'protocol': 'PROTOCOL',
    'protocol-except': 'PROTOCOL_EXCEPT',
    'qos': 'QOS',
    'routing-instance': 'ROUTING_INSTANCE',
    'source-address': 'SADDR',
    'source-exclude': 'SADDREXCLUDE',
    'source-interface': 'SINTERFACE',
    'source-prefix': 'SPFX',
    'source-port': 'SPORT',
    'source-tag': 'STAG',
    'target': 'TARGET',
    'term': 'TERM',
    'timeout': 'TIMEOUT',
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
  r'\w+([-_+.@/]\w*)*'
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
                | term_spec expiration_spec
                | term_spec fragment_offset_spec
                | term_spec icmp_type_spec
                | term_spec interface_spec
                | term_spec logging_spec
                | term_spec losspriority_spec
                | term_spec option_spec
                | term_spec owner_spec
                | term_spec packet_length_spec
                | term_spec platform_spec
                | term_spec policer_spec
                | term_spec port_spec
                | term_spec precedence_spec
                | term_spec principals_spec
                | term_spec prefix_list_spec
                | term_spec protocol_spec
                | term_spec qos_spec
                | term_spec routinginstance_spec
                | term_spec tag_list_spec
                | term_spec timeout_spec
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
  """ precedence_spec : PRECEDENCE ':' ':' one_or_more_ints """
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
                   | ADDREXCLUDE ':' ':' one_or_more_strings
                   | PROTOCOL_EXCEPT ':' ':' one_or_more_strings """

  p[0] = []
  for ex in p[4]:
    if p[1].find('source-exclude') >= 0:
      p[0].append(VarType(VarType.SADDREXCLUDE, ex))
    elif p[1].find('destination-exclude') >= 0:
      p[0].append(VarType(VarType.DADDREXCLUDE, ex))
    elif p[1].find('address-exclude') >= 0:
      p[0].append(VarType(VarType.ADDREXCLUDE, ex))
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
                | DPORT ':' ':' one_or_more_strings
                | PORT ':' ':' one_or_more_strings """
  p[0] = []
  for port in p[4]:
    if p[1].find('source-port') >= 0:
      p[0].append(VarType(VarType.SPORT, port))
    elif p[1].find('destination-port') >= 0:
      p[0].append(VarType(VarType.DPORT, port))
    else:
      p[0].append(VarType(VarType.PORT, port))


def p_protocol_spec(p):
  """ protocol_spec : PROTOCOL ':' ':' strings_or_ints """
  p[0] = []
  for proto in p[4]:
    p[0].append(VarType(VarType.PROTOCOL, proto))


def p_tag_list_spec(p):
  """ tag_list_spec : DTAG ':' ':' one_or_more_strings
                    | STAG ':' ':' one_or_more_strings """
  p[0] = []
  for tag in p[4]:
    if p[1].find('source-tag') >= 0:
      p[0].append(VarType(VarType.STAG, tag))
    elif p[1].find('destination-tag') >= 0:
      p[0].append(VarType(VarType.DTAG, tag))


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

def p_principals_spec(p):
  """ principals_spec : PRINCIPALS ':' ':' one_or_more_strings """
  p[0] = []
  for opt in p[4]:
    p[0].append(VarType(VarType.PRINCIPALS, opt))

def p_action_spec(p):
  """ action_spec : ACTION ':' ':' STRING """
  p[0] = VarType(VarType.ACTION, p[4])


def p_counter_spec(p):
  """ counter_spec : COUNTER ':' ':' STRING """
  p[0] = VarType(VarType.COUNTER, p[4])


def p_expiration_spec(p):
  """ expiration_spec : EXPIRATION ':' ':' INTEGER '-' INTEGER '-' INTEGER """
  p[0] = VarType(VarType.EXPIRATION, datetime.date(int(p[4]),
                                                   int(p[6]),
                                                   int(p[8])))


def p_comment_spec(p):
  """ comment_spec : COMMENT ':' ':' DQUOTEDSTRING """
  p[0] = VarType(VarType.COMMENT, p[4])


def p_owner_spec(p):
  """ owner_spec : OWNER ':' ':' STRING """
  p[0] = VarType(VarType.OWNER, p[4])


def p_verbatim_spec(p):
  """ verbatim_spec : VERBATIM ':' ':' STRING DQUOTEDSTRING """
  p[0] = VarType(VarType.VERBATIM, [p[4], p[5].strip('"')])


def p_qos_spec(p):
  """ qos_spec : QOS ':' ':' STRING """
  p[0] = VarType(VarType.QOS, p[4])


def p_interface_spec(p):
  """ interface_spec : SINTERFACE ':' ':' STRING
                     | DINTERFACE ':' ':' STRING """
  if p[1].find('source-interface') >= 0:
    p[0] = VarType(VarType.SINTERFACE, p[4])
  elif p[1].find('destination-interface') >= 0:
    p[0] = VarType(VarType.DINTERFACE, p[4])


def p_platform_spec(p):
  """ platform_spec : PLATFORM ':' ':' one_or_more_strings
                    | PLATFORMEXCLUDE ':' ':' one_or_more_strings """
  p[0] = []
  for platform in p[4]:
    if p[1].find('platform-exclude') >= 0:
      p[0].append(VarType(VarType.PLATFORMEXCLUDE, platform))
    elif p[1].find('platform') >= 0:
      p[0].append(VarType(VarType.PLATFORM, platform))


def p_timeout_spec(p):
  """ timeout_spec : TIMEOUT ':' ':' INTEGER """
  p[0] = VarType(VarType.TIMEOUT, p[4])


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


def p_one_or_more_ints(p):
  """ one_or_more_ints : one_or_more_ints INTEGER
                      | INTEGER
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


def memoize(obj):
  """Memoize decorator for objects that take args and or kwargs."""

  cache = obj.cache = {}

  @wraps(obj)
  def memoizer(*args, **kwargs):
    key = (args, tuple(zip(kwargs.iteritems())))
    try:
      return cache[key]
    except KeyError:
      value = obj(*args, **kwargs)
      cache[key] = value
      return value
  return memoizer


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
  for index, line in enumerate(lines):
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


def ParseFile(filename, definitions=None, optimize=True, base_dir='',
              shade_check=False):
  """Parse the policy contained in file, optionally provide a naming object.

  Read specified policy file and parse into a policy object.

  Args:
    filename: Name of policy file to parse.
    definitions: optional naming library definitions object.
    optimize: bool - whether to summarize networks and services.
    base_dir: base path string to look for acls or include files.
    shade_check: bool - whether to raise an exception when a term is shaded.

  Returns:
    policy object.
  """
  data = _ReadFile(filename)
  p = ParsePolicy(data, definitions, optimize, base_dir=base_dir,
                  shade_check=shade_check)
  return p


@memoize
def CacheParseFile(*args, **kwargs):
  """Same as ParseFile, but cached if possible.

  If this was previously called with same args/kwargs, then just return
  the previous result from cache.

  See the ParseFile function for signature details.
  """

  return ParseFile(*args, **kwargs)


def ParsePolicy(data, definitions=None, optimize=True, base_dir='',
                shade_check=False):
  """Parse the policy in 'data', optionally provide a naming object.

  Parse a blob of policy text into a policy object.

  Args:
    data: a string blob of policy data to parse.
    definitions: optional naming library definitions object.
    optimize: bool - whether to summarize networks and services.
    base_dir: base path string to look for policies or include files.
    shade_check: bool - whether to raise an exception when a term is shaded.

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
    if shade_check:
      globals()['_SHADE_CHECK'] = True

    lexer = lex.lex()

    preprocessed_data = '\n'.join(_Preprocess(data, base_dir=base_dir))
    p = yacc.yacc(write_tables=False, debug=0, errorlog=yacc.NullLogger())

    return p.parse(preprocessed_data, lexer=lexer)

  except IndexError:
    return False


# If you call this from the command line, you can specify a policy file for it
# to read.
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
