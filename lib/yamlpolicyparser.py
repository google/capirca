# Copyright 2016 Jeff Zohrab. All Rights Reserved.
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

__author__ = ['jzohrab@gmail.com']

import datetime
import os
import sys

import logging
from lib import nacaddr
from lib import naming

from lib import policy
from policy import Policy, Header, Target, Term
import yaml

class YamlPolicyParser(object):
  """Parses YAML policy file, returns Policy object."""

  def __init__(self, definitions, optimize):
    """Constructor.

    Args:
      definitions: lib.naming.Naming instance, or substitute
        - must support GetNetAddr(token) and GetServiceByProto(port, proto)
    """
    self.definitions = definitions
    self.optimize = optimize

  def parse(self, yml_string, shade_check=False):
    """Parses string, returns Policy object."""
    yml = yaml.load(yml_string)

    header = Header()
    header.Name = yml['name']
    if 'comment' in yml:
      header.comment.append(yml['comment'])

    for ta in YamlPolicyParser.transform_targets_to_Capirca_style(yml):
      tgt = Target(ta)
      header.target.append(tgt)

    terms = map(self._parse_term, yml['terms'])
    translate_terms(terms, self.definitions, self.optimize)

    p = Policy(header, terms, shade_check)

    return p


  @staticmethod
  def build_Capirca_Target_ctor_array(target, name, addressfamily):
    """Make args for a single Capirca policy.Target's constructor.

    Capirca Target specs are currently "loose", in that the target
    data load via .pol files doesn't have strong parsing: the data
    pulled from .pol files is passed to the Target constructor as a
    simple list of strings, and it's assumed (perhaps elsewhere in the
    models) that the data is valid.

    The Target ctor data is pulled from different locations in the
    yaml file: the ACL name and address-family are at the top of the
    file, and the targets are listed afterwards.  The individual
    target lines can contain overrides for the address-family.

    This section of the spec should be tightened, as it is currently
    too permissive.

    Args:
      hsh: hash from a .yml policy file

    Returns:
      array of Capirca-style Target data for the policy.Target constructor.

    Public static for unit testing.

    """
    ta = target.split()
    ret = []

    if ta[0] == 'cisco':
      ret = ['cisco', name]
      if len(ta) == 1:
        family = { 'ipv4': 'extended', 'ipv6': 'inet6' }
        ret.extend([family[addressfamily]])
      else:
        ret.extend(ta[1:])
    elif ta[0] == 'juniper':
      ret = ['juniper', name]
      if len(ta) == 1:
        family = { 'ipv4': 'inet', 'ipv6': 'inet6' }
        ret.extend([family[addressfamily]])
      else:
        ret.extend(ta[1:])
    elif ta[0] == 'nsxv':
      ret = ['nsxv']
      family = { 'ipv4': 'inet', 'ipv6': 'inet6' }
      ret.extend([family[addressfamily]])
      ret.extend(ta[1:])
    elif ta[0] in ('demo', 'arista', 'brocade', 'ciscoxr', 'cisconx', 'packetfilter'):
      ret = [ta[0], name]
      ret.extend(ta[1:])
    elif ta[0] in ('gce', 'ipset', 'speedway', 'ciscoasa', 'srx'):
      # Leave as-is
      ret = ta
    else:
      raise ValueError('unhandled target spec {0}'.format(target))

    return ret

  @staticmethod
  def transform_targets_to_Capirca_style(hsh):
    """Creating Capirca policy.Targets from YAML.
    Public static for unit testing.
    """
    aclname = hsh['name']
    addrfamily = hsh['address-family']
    b = lambda x: YamlPolicyParser.build_Capirca_Target_ctor_array(x, aclname, addrfamily)
    return map(b, hsh['targets'])


  def _parse_term(self, yml):
    """Creates a new Term object from supplied yaml."""
    term = Term()
    for key, value in yml.iteritems():
      self._parse_term_spec(term, key, value)
    return term

  def _parse_term_spec(self, term, key, value):

    def print_name(x):
      # print 'processing term ' + x
      term.name = x

    # TODO fix: move this to model
    def append_action(a):
      possible_actions = set(('accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'))
      if a not in possible_actions:
        raise InvalidTermActionError('%s is not a valid action' % obj)
      term.action.append(a)

    def set_vpn(v):
      term.vpn = (v[0], v[1])

    def append_logging(a):
      possible_logging = set(('true', 'True', 'syslog', 'local', 'disable', 'log-both'))
      if a == True:  # PyYAML reads 'true' in a .yml as True; hack force to string.
        a = 'true'
      if a not in possible_logging:
        raise InvalidTermLoggingError('%s is not a valid logging option', a)
      term.logging.append(a)

    def set_next_ip(addresses_string):
      term.next_ip = self.definitions.GetNetAddr(tok)

    def split_tokens(s): return [t.strip() for t in s.split(',') if t.strip() != '']

    def map_addr_tokens(addresses_string):
      # return map(self.definitions.GetNetAddr, split_tokens(addresses_string))
      ret = []
      for tok in split_tokens(addresses_string):
        ret.extend(self.definitions.GetNetAddr(tok))
      return ret

    # map of the directives to the operation to perform.
    # If the operation is a string, this is assumed to be a term
    # attribute name.
    ops_map = {
      'name': print_name,
      'action': append_action,
      'address': (map_addr_tokens, term.address.extend),
      'address-exclude': (map_addr_tokens, term.address_exclude.extend),
      'comment': term.comment.append,
      'counter': 'counter',
      'destination-address': (map_addr_tokens, term.destination_address.extend),
      'destination-exclude': (map_addr_tokens, term.destination_address_exclude.extend),
      'destination-interface': 'destination_interface',
      'destination-prefix': (split_tokens, term.destination_prefix.extend),
      'destination-port': (split_tokens, term.destination_port.extend),
      'destination-tag':  (split_tokens, term.destination_tag.extend),
      'dscp-except': term.dscp_except.append,
      'dscp-match': term.dscp_match.append,
      'dscp-set': 'dscp_set',
      'ether-type': (split_tokens, term.ether_type.extend),
      'expiration': 'expiration',
      'forwarding-class': 'forwarding_class',
      'fragment-offset': 'fragment_offset',
      'hop-limit': 'hop_limit',
      'icmp-type': (split_tokens, term.icmp_type.extend),
      'logging': append_logging,
      'loss-priority': 'loss_priority',
      'next-ip': set_next_ip,
      'option': (split_tokens, term.option.extend),
      'owner': 'owner',
      'packet-length': 'packet_length',
      'platform': (split_tokens, term.platform.extend),
      'platform-exclude': (split_tokens, term.platform_exclude.extend),
      'policer': 'policer',
      'port': (split_tokens, term.port.extend),
      'precedence': (split_tokens, term.precedence.extend),
      'principals': (split_tokens, term.principals.extend),
      'protocol': (split_tokens, term.protocol.extend),
      'protocol-except': (split_tokens, term.protocol_except.extend),
      'qos': 'qos',
      'routing-instance': 'routing_instance',
      'source-address': (map_addr_tokens, term.source_address.extend),
      'source-exclude': (map_addr_tokens, term.source_address_exclude.extend),
      'source-interface': 'source_interface',
      'source-prefix': (split_tokens, term.source_prefix.extend),
      'source-port': (split_tokens, term.source_port.extend),
      'source-tag': (split_tokens, term.source_tag.extend),
      'timeout': 'timeout',
      'traffic-type': (split_tokens, term.traffic_type.extend),
      'verbatim': term.verbatim.append,
      'vpn': set_vpn,
    }

    op = ops_map.get(key, None)

    if op is None:
      raise TermObjectTypeError('Unknown term type ' + key)

    if type(op) is str:
      setattr(term, op, value)
      return

    if type(op) is tuple:
      value = op[0](value)
      op = op[1]
    op(value)


############################


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


class ShadingError(Error):
  """Error when a term is shaded by a prior term."""


# TODO fix: add tests for this
def translate_terms(terms, definitions, optimize):
    """."""
    if not terms:
      raise NoTermsError('no terms found')
    for term in terms:
      if term.translated:
        continue
      if term.port:
        term.port = __translate_ports(term.port, term.protocol, term.name, definitions)
        if not term.port:
          raise TermPortProtocolError(
              'no ports of the correct protocol for term %s' % (
                  term.name))
      if term.source_port:
        term.source_port = __translate_ports(term.source_port, term.protocol,
                                             term.name, definitions)
        if not term.source_port:
          raise TermPortProtocolError(
              'no source ports of the correct protocol for term %s' % (
                  term.name))
      if term.destination_port:
        term.destination_port = __translate_ports(term.destination_port,
                                                  term.protocol, term.name, definitions)
        if not term.destination_port:
          raise TermPortProtocolError(
              'no destination ports of the correct protocol for term %s' % (
                  term.name))

      # If argument is true, we optimize, otherwise just sort addresses
      term.AddressCleanup(optimize)

      term.SanityCheck()
      term.translated = True

def __translate_ports(ports, protocols, term_name, definitions):
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
      service_by_proto = definitions.GetServiceByProto(port, proto)
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

    if definitions is None:
      definitions = naming.Naming('./def')

    p = YamlPolicyParser(definitions, optimize)
    preprocessed_data = '\n'.join(_Preprocess(data, base_dir=base_dir))
    return p.parse(preprocessed_data, shade_check)

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

