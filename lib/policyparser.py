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

__author__ = ['pmoody@google.com',
              'watson@google.com']

import datetime
import os
import sys

import logging
from lib import nacaddr
from lib import naming

from lib import policy
from policy import Policy, Header, Target, Term
from ply import lex
from ply import yacc


DEFINITIONS = None
DEFAULT_DEFINITIONS = './def'
ACTIONS = set(('accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'))
_LOGGING = set(('true', 'True', 'syslog', 'local', 'disable', 'log-both'))
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


class TermAddressExclusionError(Error):
  """Excluded address block is not contained in the accepted address block."""


class TermObjectTypeError(Error):
  """Error with an object passed to Term."""


class TermPortProtocolError(Error):
  """Error when a requested protocol doesn't have any of the requested ports."""


class TermNoActionError(Error):
  """Error when a term hasn't defined an action."""


class InvalidTermActionError(Error):
  """Error when an action is invalid."""


class InvalidTermLoggingError(Error):
  """Error when a option is set for logging."""


class UndefinedAddressError(Error):
  """Error when an undefined address is referenced."""


class NoTermsError(Error):
  """Error when no terms were found."""


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
  VPN = 37
  APPLY_GROUPS = 38
  APPLY_GROUPS_EXCEPT = 39
  DSCP_SET = 40
  DSCP_MATCH = 41
  DSCP_EXCEPT = 42
  FORWARDING_CLASS = 43
  STAG = 44
  DTAG = 45
  NEXT_IP = 46
  HOP_LIMIT = 47

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
    return str(self.value)

  def __repr__(self):
    return self.__str__()

  def __eq__(self, other):
    return self.var_type == other.var_type and self.value == other.value


# Lexing/Parsing starts here
tokens = (
    'ACTION',
    'ADDR',
    'ADDREXCLUDE',
    'COMMENT',
    'COUNTER',
    'DADDR',
    'DADDREXCLUDE',
    'DINTERFACE',
    'DPFX',
    'DPORT',
    'DQUOTEDSTRING',
    'DSCP',
    'DSCP_EXCEPT',
    'DSCP_MATCH',
    'DSCP_RANGE',
    'DSCP_SET',
    'DTAG',
    'ESCAPEDSTRING',
    'ETHER_TYPE',
    'EXPIRATION',
    'FORWARDING_CLASS',
    'FRAGMENT_OFFSET',
    'HOP_LIMIT',
    'APPLY_GROUPS',
    'APPLY_GROUPS_EXCEPT',
    'HEADER',
    'ICMP_TYPE',
    'INTEGER',
    'LOGGING',
    'LOSS_PRIORITY',
    'NEXT_IP',
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
    'VPN',
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
    'dscp-except': 'DSCP_EXCEPT',
    'dscp-match': 'DSCP_MATCH',
    'dscp-set': 'DSCP_SET',
    'ether-type': 'ETHER_TYPE',
    'expiration': 'EXPIRATION',
    'forwarding-class': 'FORWARDING_CLASS',
    'fragment-offset': 'FRAGMENT_OFFSET',
    'hop-limit': 'HOP_LIMIT',
    'apply-groups': 'APPLY_GROUPS',
    'apply-groups-except': 'APPLY_GROUPS_EXCEPT',
    'header': 'HEADER',
    'icmp-type': 'ICMP_TYPE',
    'logging': 'LOGGING',
    'loss-priority': 'LOSS_PRIORITY',
    'next-ip': 'NEXT_IP',
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
    'vpn': 'VPN',
}


# disable linting warnings for lexx/yacc code
# pylint: disable=unused-argument,invalid-name,g-short-docstring-punctuation
# pylint: disable=g-docstring-quotes,g-short-docstring-space
# pylint: disable=g-space-before-docstring-summary,g-doc-args
# pylint: disable=g-no-space-after-docstring-summary
# pylint: disable=g-docstring-missing-newline

def t_IGNORE_COMMENT(t):
  r'\#.*'
  pass


def t_ESCAPEDSTRING(t):
  r'"([^"\\]*(?:\\"[^"\\]*)+)"'
  t.lexer.lineno += str(t.value).count('\n')
  return t

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


def t_DSCP_RANGE(t):
  # pylint: disable=line-too-long
  r'\b((b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))([-]{1})((b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))\b'
  t.type = reserved.get(t.value, 'DSCP_RANGE')
  return t

def t_DSCP(t):
  r'\b((b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))\b'
  t.type = reserved.get(t.value, 'DSCP')
  return t


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
    terms = p[3]
    __translate_terms(terms)
    if type(p[1]) is Policy:
      p[1].AddFilter(p[2], p[3])
      p[0] = p[1]
    else:
      p[0] = Policy(p[2], p[3], _SHADE_CHECK)


def __translate_terms(terms):
    """."""
    if not terms:
      raise NoTermsError('no terms found')
    for term in terms:
      if term.translated:
        continue
      if term.port:
        term.port = __translate_ports(term.port, term.protocol, term.name)
        if not term.port:
          raise TermPortProtocolError(
              'no ports of the correct protocol for term %s' % (
                  term.name))
      if term.source_port:
        term.source_port = __translate_ports(term.source_port, term.protocol,
                                          term.name)
        if not term.source_port:
          raise TermPortProtocolError(
              'no source ports of the correct protocol for term %s' % (
                  term.name))
      if term.destination_port:
        term.destination_port = __translate_ports(term.destination_port,
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

def __translate_ports(ports, protocols, term_name):
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


def p_header(p):
  """ header : HEADER '{' header_spec '}' """
  p[0] = p[3]


def p_header_spec(p):
  """ header_spec : header_spec target_spec
                  | header_spec comment_spec
                  | header_spec apply_groups_spec
                  | header_spec apply_groups_except_spec
                  | """
  if len(p) > 1:
    if type(p[1]) == Header:
      __add_header_vartype_obj(p[1], p[2])
      p[0] = p[1]
    else:
      p[0] = Header()
      __add_header_vartype_obj(p[0], p[2])

def __add_header_vartype_obj(header, obj):
  """Add an object to the Header.

  Args:
    header: the Header
    obj: of type VarType.COMMENT, VarType.APPLY_GROUPS,
    VarType.APPLY_GROUPS_EXCEPT, or Target

  Raises:
    RuntimeError: if object type cannot be determined
  """
  if type(obj) == Target:
    header.target.append(obj)
  elif isinstance(obj, list) and all(isinstance(x, VarType) for x in obj):
    for x in obj:
      if x.var_type == VarType.APPLY_GROUPS:
        header.apply_groups.append(str(x))
      elif x.var_type == VarType.APPLY_GROUPS_EXCEPT:
        header.apply_groups_except.append(str(x))
  elif obj.var_type == VarType.COMMENT:
    header.comment.append(str(obj))
  else:
    raise RuntimeError('Unable to add object from header.')

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
                | term_spec dscp_set_spec
                | term_spec dscp_match_spec
                | term_spec dscp_except_spec
                | term_spec ether_type_spec
                | term_spec exclude_spec
                | term_spec expiration_spec
                | term_spec forwarding_class_spec
                | term_spec fragment_offset_spec
                | term_spec hop_limit_spec
                | term_spec icmp_type_spec
                | term_spec interface_spec
                | term_spec logging_spec
                | term_spec losspriority_spec
                | term_spec next_ip_spec
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
                | term_spec vpn_spec
                | """
  if len(p) > 1:
    if type(p[1]) == Term:
      __add_term_vartype_obj(p[1], p[2])
      p[0] = p[1]
    else:
      t = Term()
      p[0] = t
      __add_term_vartype_obj(t, p[2])


def __add_term_vartype_obj(term, obj):
  """Add an object of unknown type to this term.

  Args:
    obj: single or list of either
      [Address, Port, Option, Protocol, Counter, Action, Comment, Expiration]

  Raises:
    InvalidTermActionError: if the action defined isn't an accepted action.
      eg, action:: godofoobar
    TermObjectTypeError: if __add_term_vartype_obj is called with an object it doesn't
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
        term.source_address.extend(saddr)
      elif x.var_type is VarType.DADDRESS:
        daddr = DEFINITIONS.GetNetAddr(x.value)
        term.destination_address.extend(daddr)
      elif x.var_type is VarType.ADDRESS:
        addr = DEFINITIONS.GetNetAddr(x.value)
        term.address.extend(addr)
      # do we have address excludes?
      elif x.var_type is VarType.SADDREXCLUDE:
        saddr_exclude = DEFINITIONS.GetNetAddr(x.value)
        term.source_address_exclude.extend(saddr_exclude)
      elif x.var_type is VarType.DADDREXCLUDE:
        daddr_exclude = DEFINITIONS.GetNetAddr(x.value)
        term.destination_address_exclude.extend(daddr_exclude)
      elif x.var_type is VarType.ADDREXCLUDE:
        addr_exclude = DEFINITIONS.GetNetAddr(x.value)
        term.address_exclude.extend(addr_exclude)
      # do we have a list of ports?
      elif x.var_type is VarType.PORT:
        term.port.append(x.value)
      elif x.var_type is VarType.SPORT:
        term.source_port.append(x.value)
      elif x.var_type is VarType.DPORT:
        term.destination_port.append(x.value)
      # do we have a list of protocols?
      elif x.var_type is VarType.PROTOCOL:
        term.protocol.append(x.value)
      # do we have a list of protocol-exceptions?
      elif x.var_type is VarType.PROTOCOL_EXCEPT:
        term.protocol_except.append(x.value)
      # do we have a list of options?
      elif x.var_type is VarType.OPTION:
        term.option.append(x.value)
      elif x.var_type is VarType.PRINCIPALS:
        term.principals.append(x.value)
      elif x.var_type is VarType.SPFX:
        term.source_prefix.append(x.value)
      elif x.var_type is VarType.DPFX:
        term.destination_prefix.append(x.value)
      elif x.var_type is VarType.ETHER_TYPE:
        term.ether_type.append(x.value)
      elif x.var_type is VarType.TRAFFIC_TYPE:
        term.traffic_type.append(x.value)
      elif x.var_type is VarType.PRECEDENCE:
        term.precedence.append(x.value)
      elif x.var_type is VarType.FORWARDING_CLASS:
        term.forwarding_class = obj.value
      elif x.var_type is VarType.NEXT_IP:
        term.next_ip = DEFINITIONS.GetNetAddr(x.value)
      elif x.var_type is VarType.PLATFORM:
        term.platform.append(x.value)
      elif x.var_type is VarType.PLATFORMEXCLUDE:
        term.platform_exclude.append(x.value)
      elif x.var_type is VarType.DSCP_MATCH:
        term.dscp_match.append(x.value)
      elif x.var_type is VarType.DSCP_EXCEPT:
        term.dscp_except.append(x.value)
      elif x.var_type is VarType.STAG:
        term.source_tag.append(x.value)
      elif x.var_type is VarType.DTAG:
        term.destination_tag.append(x.value)
      else:
        raise TermObjectTypeError(
            '%s isn\'t a type I know how to deal with (contains \'%s\')' % (
                type(x), x.value))
  else:
    # stupid no switch statement in python
    if obj.var_type is VarType.COMMENT:
      term.comment.append(str(obj))
    elif obj.var_type is VarType.OWNER:
      term.owner = obj.value
    elif obj.var_type is VarType.EXPIRATION:
      term.expiration = obj.value
    elif obj.var_type is VarType.LOSS_PRIORITY:
      term.loss_priority = obj.value
    elif obj.var_type is VarType.ROUTING_INSTANCE:
      term.routing_instance = obj.value
    elif obj.var_type is VarType.PRECEDENCE:
      term.precedence = obj.value
    elif obj.var_type is VarType.FORWARDING_CLASS:
      term.forwarding_class = obj.value
    elif obj.var_type is VarType.NEXT_IP:
      term.next_ip = DEFINITIONS.GetNetAddr(obj.value)
    elif obj.var_type is VarType.VERBATIM:
      term.verbatim.append(obj)
    elif obj.var_type is VarType.ACTION:
      if str(obj) not in ACTIONS:
        raise InvalidTermActionError('%s is not a valid action' % obj)
      term.action.append(obj.value)
    elif obj.var_type is VarType.COUNTER:
      term.counter = obj
    elif obj.var_type is VarType.ICMP_TYPE:
      term.icmp_type.extend(obj.value)
    elif obj.var_type is VarType.LOGGING:
      if str(obj) not in _LOGGING:
        raise InvalidTermLoggingError('%s is not a valid logging option' %
                                      obj)
      term.logging.append(obj)
    # police man, tryin'a take you jail
    elif obj.var_type is VarType.POLICER:
      term.policer = obj.value
    # qos?
    elif obj.var_type is VarType.QOS:
      term.qos = obj.value
    elif obj.var_type is VarType.PACKET_LEN:
      term.packet_length = obj.value
    elif obj.var_type is VarType.FRAGMENT_OFFSET:
      term.fragment_offset = obj.value
    elif obj.var_type is VarType.HOP_LIMIT:
      term.hop_limit = obj.value
    elif obj.var_type is VarType.SINTERFACE:
      term.source_interface = obj.value
    elif obj.var_type is VarType.DINTERFACE:
      term.destination_interface = obj.value
    elif obj.var_type is VarType.TIMEOUT:
      term.timeout = obj.value
    elif obj.var_type is VarType.DSCP_SET:
      term.dscp_set = obj.value
    elif obj.var_type is VarType.VPN:
      term.vpn = (obj.value[0], obj.value[1])
    else:
      raise TermObjectTypeError(
          '%s isn\'t a type I know how to deal with' % (type(obj)))


def p_routinginstance_spec(p):
  """ routinginstance_spec : ROUTING_INSTANCE ':' ':' STRING """
  p[0] = VarType(VarType.ROUTING_INSTANCE, p[4])


def p_losspriority_spec(p):
  """ losspriority_spec :  LOSS_PRIORITY ':' ':' STRING """
  p[0] = VarType(VarType.LOSS_PRIORITY, p[4])


def p_precedence_spec(p):
  """ precedence_spec : PRECEDENCE ':' ':' one_or_more_ints """
  p[0] = VarType(VarType.PRECEDENCE, p[4])


def p_forwarding_class_spec(p):
  """ forwarding_class_spec : FORWARDING_CLASS ':' ':' STRING """
  p[0] = VarType(VarType.FORWARDING_CLASS, p[4])


def p_next_ip_spec(p):
  """ next_ip_spec : NEXT_IP ':' ':' STRING """
  p[0] = VarType(VarType.NEXT_IP, p[4])


def p_icmp_type_spec(p):
  """ icmp_type_spec : ICMP_TYPE ':' ':' one_or_more_strings """
  p[0] = VarType(VarType.ICMP_TYPE, p[4])


def p_packet_length_spec(p):
  """ packet_length_spec : PACKET_LEN ':' ':' INTEGER
                         | PACKET_LEN ':' ':' INTEGER '-' INTEGER """
  if len(p) == 5:
    p[0] = VarType(VarType.PACKET_LEN, str(p[4]))
  else:
    p[0] = VarType(VarType.PACKET_LEN, str(p[4]) + '-' + str(p[6]))


def p_fragment_offset_spec(p):
  """ fragment_offset_spec : FRAGMENT_OFFSET ':' ':' INTEGER
                           | FRAGMENT_OFFSET ':' ':' INTEGER '-' INTEGER """
  if len(p) == 5:
    p[0] = VarType(VarType.FRAGMENT_OFFSET, str(p[4]))
  else:
    p[0] = VarType(VarType.FRAGMENT_OFFSET, str(p[4]) + '-' + str(p[6]))


def p_hop_limit_spec(p):
  """ hop_limit_spec : HOP_LIMIT ':' ':' INTEGER
                     | HOP_LIMIT ':' ':' INTEGER '-' INTEGER """
  if len(p) == 5:
    p[0] = VarType(VarType.HOP_LIMIT, str(p[4]))
  else:
    p[0] = VarType(VarType.HOP_LIMIT, str(p[4]) + '-' + str(p[6]))


def p_one_or_more_dscps(p):
  """ one_or_more_dscps : one_or_more_dscps DSCP_RANGE
                        | one_or_more_dscps DSCP
                        | one_or_more_dscps INTEGER
                        | DSCP_RANGE
                        | DSCP
                        | INTEGER """
  if len(p) > 1:
    if type(p[1]) is list:
      p[1].append(p[2])
      p[0] = p[1]
    else:
      p[0] = [p[1]]


def p_dscp_set_spec(p):
  """ dscp_set_spec : DSCP_SET ':' ':' DSCP
                    | DSCP_SET ':' ':' INTEGER """
  p[0] = VarType(VarType.DSCP_SET, p[4])


def p_dscp_match_spec(p):
  """ dscp_match_spec : DSCP_MATCH ':' ':' one_or_more_dscps """
  p[0] = []
  for dscp in p[4]:
    p[0].append(VarType(VarType.DSCP_MATCH, dscp))


def p_dscp_except_spec(p):
  """ dscp_except_spec : DSCP_EXCEPT ':' ':' one_or_more_dscps """
  p[0] = []
  for dscp in p[4]:
    p[0].append(VarType(VarType.DSCP_EXCEPT, dscp))


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
  """ verbatim_spec : VERBATIM ':' ':' STRING DQUOTEDSTRING
                    | VERBATIM ':' ':' STRING ESCAPEDSTRING """
  p[0] = VarType(VarType.VERBATIM, [p[4], p[5].strip('"').replace('\\"', '"')])


def p_vpn_spec(p):
  """ vpn_spec : VPN ':' ':' STRING STRING
               | VPN ':' ':' STRING """
  if len(p) == 6:
    p[0] = VarType(VarType.VPN, [p[4], p[5]])
  else:
    p[0] = VarType(VarType.VPN, [p[4], ''])


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


def p_apply_groups_spec(p):
  """ apply_groups_spec : APPLY_GROUPS ':' ':' one_or_more_strings """
  p[0] = []
  for group in p[4]:
    p[0].append(VarType(VarType.APPLY_GROUPS, group))


def p_apply_groups_except_spec(p):
  """ apply_groups_except_spec : APPLY_GROUPS_EXCEPT ':' ':' one_or_more_strings
  """
  p[0] = []
  for group_except in p[4]:
    p[0].append(VarType(VarType.APPLY_GROUPS_EXCEPT, group_except))


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

# pylint: enable=unused-argument,invalid-name,g-short-docstring-punctuation
# pylint: enable=g-docstring-quotes,g-short-docstring-space
# pylint: enable=g-space-before-docstring-summary,g-doc-args
# pylint: enable=g-no-space-after-docstring-summary
# pylint: enable=g-docstring-missing-newline


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
  logging.debug('ReadFile(%s)', filename)
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
  for line in [x.rstrip() for x in data.splitlines()]:
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
    policy object or False (if parse error).
  """
  data = _ReadFile(filename)
  p = ParsePolicy(data, definitions, optimize, base_dir=base_dir,
                  shade_check=shade_check)
  return p


def ParsePolicy(data, definitions=None, optimize=True, base_dir='',
                shade_check=False):
  """Parse the policy in 'data', optionally provide a naming object.

  Parse a blob of policy text into a policy object.

  Args:
    data: a string blob of policy data to parse.
    definitions: optional naming library definitions object.
    optimize: bool - whether to summarize networks and services.
    base_dir: base path string to look for acls or include files.
    shade_check: bool - whether to raise an exception when a term is shaded.

  Returns:
    policy object or False (if parse error).
  """
  try:
    global DEFINITIONS
    global _OPTIMIZE
    global _SHADE_CHECK

    if definitions:
      DEFINITIONS = definitions
    else:
      DEFINITIONS = naming.Naming(DEFAULT_DEFINITIONS)

    globals()['_OPTIMIZE'] = optimize
    globals()['_SHADE_CHECK'] = shade_check

    lexer = lex.lex()

    preprocessed_data = '\n'.join(_Preprocess(data, base_dir=base_dir))
    p = yacc.yacc(write_tables=False, debug=0, errorlog=yacc.NullLogger())

    return p.parse(preprocessed_data, lexer=lexer)

  except IndexError:
    return False


# If you call this from the command line, you can specify a pol file for it
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

