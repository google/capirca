#!/usr/bin/python
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


"""Cisco renderer."""

__author__ = 'pmoody@google.com (Peter Moody)'

import socket
import logging

from third_party import ipaddr
import nacaddr


_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
    }


def FixupProtocol(proto):
  """Numeric representation of the protocol.

  Arg:
    proto: the protocol, eg, 'tcp', 'ip'

  Returns:
    the numeric representation, eg 6, or 'ip' in the case
    of 'ip' being the proto.  thank you cisco.
  """
  ret = proto
  if type(proto) is str:
    try:
      ret = socket.getprotobyname(proto.lower())
    except socket.error:
      ret = proto
  return ret


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


class TermStandard(object):
  """A single standard ACL Term."""

  def __init__(self, term, filter_name):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    # sanity checking for standard acls
    if self.term.protocol:
      raise StandardAclTermError(
          'Standard ACLs cannot specify protocols')
    if (self.term.source_address
        or self.term.source_address_exclude
        or self.term.destination_address
        or self.term.destination_address_exclude):
      raise StandardAclTermError(
          'Standard ACLs cannot use source or destination addresses')
    if self.term.option:
      raise StandardAclTermError(
          'Standard ACLs prohibit use of options')
    if self.term.source_port or self.term.destination_port:
      raise StandardAclTermError(
          'Standard ACLs prohibit use of port numbers')
    if self.term.counter:
      raise StandardAclTermError(
          'Counters are not implemented in standard ACLs')
    if self.term.logging:
      raise StandardAclTermError(
          'Logging is not implemented in standard ACLs')

  def __str__(self):
    ret_str = []

    ret_str.append('remark ' + self.term.name)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('remark ' + str(line))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next in self.term.verbatim:
        if next.value[0] == 'cisco':
          ret_str.append(str(next.value[1]))
        return '\n'.join(ret_str)

    for addr in self.term.address:
      if type(addr) is nacaddr.IPv6:
        logging.debug('Ignoring unsupported IPv6 address in "%s"',
                      self.term.name)
      else:
        action = _ACTION_TABLE.get(str(self.term.action[0]))
        if addr.prefixlen == 32:
          ret_str.append('access-list %s %s %s' % (self.filter_name,
                                                   action,
                                                   addr.ip_ext))
        else:
          ret_str.append('access-list %s %s %s %s' % (self.filter_name,
                                                      action,
                                                      addr.network_ext,
                                                      addr.hostmask_ext))

    return '\n'.join(ret_str)


class ObjectGroup(object):
  """Used for printing out the object group definitions.

  since the ports don't store the token name information, we have
  to fudge their names.  ports will be written out like

    object-group ip port <low_port>-<high_port>
      range <low-port> <high-port>
    exit

  where as the addressess can be written as

    object-group ip address first-term-source-address
      172.16.0.0
      172.20.0.0 255.255.0.0
      172.22.0.0 255.128.0.0
      172.24.0.0
      172.28.0.0
    exit
  """

  def __init__(self):
    self.filter_name = ''
    self.terms = []

  @property
  def valid(self):
    return len(self.terms) > 0

  def AddTerm(self, term):
    self.terms.append(term)

  def AddName(self, filter_name):
    self.filter_name = filter_name

  def __str__(self):
    ret_str = ['\n']
    addresses = {}
    ports = {}

    for term in self.terms:
      # I don't have an easy way get the token name used in the pol file
      # w/o reading the pol file twice (with some other library) or doing
      # some other ugly hackery. Instead, the entire block of source and dest
      # addresses for a given term is given a unique, computable name which
      # is not related to the NETWORK.net token name.  that's what you get
      # for using cisco, which has decided to implement its own meta language.

      # source address
      saddrs = term.GetAddressOfVersion('source_address', 4)
      # check to see if we've already seen this address.
      if not saddrs[0].parent_token in addresses:
        addresses[saddrs[0].parent_token] = True
        ret_str.append('object-group ip address %s' % saddrs[0].parent_token)
        for addr in saddrs:
          ret_str.append(' %s %s' % (addr.ip_ext, addr.netmask_ext))
        ret_str.append('exit\n')

      # destination address
      daddrs = term.GetAddressOfVersion('destination_address', 4)
      # check to see if we've already seen this address
      if not daddrs[0].parent_token in addresses:
        addresses[daddrs[0].parent_token] = True
        ret_str.append('object-group ip address %s' % daddrs[0].parent_token)
        for addr in term.GetAddressOfVersion('destination_address', 4):
          ret_str.append(' %s %s' % (addr.ip_ext, addr.netmask_ext))
        ret_str.append('exit\n')

      # source port
      for port in term.source_port + term.destination_port:
        if not port:
          continue
        port_key = '%s-%s' % (port[0], port[1])
        if not port_key in ports.keys():
          ports[port_key] = True
          ret_str.append('object-group ip port %s' % port_key)
          if port[0] != port[1]:
            ret_str.append(' range %d %d' % (port[0], port[1]))
          else:
            ret_str.append(' eq %d' % port[0])
          ret_str.append('exit\n')

    return '\n'.join(ret_str)


class ObjectGroupTerm(object):
  """An individual term of an object-group'd acl.

  Object Group acls are very similar to extended acls in their
  syntax expect they use a meta language with address/service
  definitions.

  eg:

    permit tcp first-term-source-address 179-179 ANY

  where first-term-source-address, ANY and 179-179 are defined elsewhere
  in the acl.
  """

  def __init__(self, term, filter_name):
    self.term = term
    self.filter_name = filter_name

  def __str__(self):
    source_address_dict = {}
    destination_address_dict = {}

    ret_str = ['\n']
    ret_str.append('remark %s' % self.term.name)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('remark %s' % str(line))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next in self.term.verbatim:
        if next.value[0] == 'cisco':
          ret_str.append(str(next.value[1]))
        return '\n'.join(ret_str)


    # protocol
    protocol = self.term.protocol
    if not protocol:
      protocol = ['ip']
    else:
      # fix the protocol, b/1746531
      protocol = map(lambda x: FixupProtocol(x), self.term.protocol)

    # addresses
    source_address = self.term.source_address
    if source_address:
      source_address = [nacaddr.IPv4('0.0.0.0/0', token='ANY')]
    source_address_dict[source_address[0].parent_token] = True

    destination_address = self.term.destination_address
    if not destination_address:
      destination_address = [nacaddr.IPv4('0.0.0.0/0', token='ANY')]
    destination_address_dict[destination_address[0].parent_token] = True

    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    for saddr in source_address_dict:
      for daddr in destination_address_dict:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              ret_str.append(
                  self._TermletToStr(_ACTION_TABLE.get(str(
                  self.term.action[0])), proto, saddr, sport, daddr, dport))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport):

    # fix addreses
    if saddr:
      saddr = 'addrgroup %s' % saddr
    if daddr:
      daddr = 'addrgroup %s' % daddr
    # fix ports
    if sport:
      sport = 'portgroup %d-%d' % (sport[0], sport[1])
    else:
      sport = ''
    if dport:
      dport = 'portgroup %d-%d' % (dport[0], dport[1])
    else:
      dport = ''

    return ' %s %s %s %s %s %s' % (
        action, proto, saddr, sport, daddr, dport)


class Term(object):
  """A single ACL Term."""

  def __init__(self, term):
    self.term = term
    self.options = []

  def __str__(self):
    ret_str = ['\n']

    ret_str.append('remark ' + self.term.name)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('remark ' + str(line)[:100])

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next in self.term.verbatim:
        if next.value[0] == 'cisco':
          ret_str.append(str(next.value[1]))
        return '\n'.join(ret_str)

    # protocol
    protocol = self.term.protocol
    if not protocol:
      protocol = ['ip']
    else:
      # fix the protocol, b/1746531
      protocol = map(lambda x: FixupProtocol(x), self.term.protocol)

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', 4)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', 4)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
    else:
      # source address not set
      source_address = ['any']

    # destination address
    if self.term.destination_address:
      destination_address = self.term.GetAddressOfVersion(
          'destination_address', 4)
      destination_address_exclude = self.term.GetAddressOfVersion(
          'destination_address_exclude', 4)
      if destination_address_exclude:
        destination_address = nacaddr.ExcludeAddrs(
            destination_address,
            destination_address_exclude)
    else:
      # destination address not set
      destination_address = ['any']

    # options
    extra_options = []
    for opt in [str(x) for x in self.term.option]:
      if opt.find('tcp-established') == 0 and 6 in self.term.protocol:
        extra_options.append('established')
        self.term.option.remove('tcp-established')
      elif opt.find('established') == 0:
        # already taken care of in policy
        self.term.option.remove('established')
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

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:

              # This is a temporary fix until inet6 support is added
              # We simply ignore creating output for inet6 src or dst addresses
              if (isinstance(saddr, nacaddr.IPv6) or
                  isinstance(daddr, nacaddr.IPv6)):
                logging.debug('Ignoring unsupported IPv6 address in "%s"',
                              self.term.name)
              else:
                ret_str.append(self._TermletToStr(
                    _ACTION_TABLE.get(str(self.term.action[0])),
                    proto,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    self.options))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str, protocl
      saddr: str or ipaddr, source address
      sport: str list or none, the source port
      daddr: str or ipaddr, the destination address
      dport: str list or none, the destination port
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.
    """

    if type(saddr) is nacaddr.IPv4 or type(saddr) is ipaddr.IPv4:
      if saddr.numhosts > 1:
        saddr = saddr.ip_ext + ' ' + saddr.hostmask_ext
      else:
        saddr = 'host ' + saddr.ip_ext

    if type(daddr) is nacaddr.IPv4 or type(daddr) is ipaddr.IPv4:
      if daddr.numhosts > 1:
        daddr = daddr.ip_ext + ' ' + daddr.hostmask_ext
      else:
        daddr = 'host ' + daddr.ip_ext

    # fix ports
    if not sport:
      sport = ''
    elif sport[0] != sport[1]:
      sport = 'range %d %d' % (sport[0], sport[1])
    else:
      sport = 'eq %d' % (sport[0])

    if not dport:
      dport = ''
    elif dport[0] != dport[1]:
      dport = 'range %d %d' % (dport[0], dport[1])
    else:
      dport = 'eq %d' % (dport[0])

    if not option:
      option = ['']

    return ' %s %s %s %s %s %s %s' % (
        action, proto, saddr, sport, daddr, dport, ' '.join(option))


class Cisco(object):
  """A cisco policy object."""

  suffix = '.acl'
  
  def __init__(self, pol):
    for header in pol.headers:
      if 'cisco' not in header.platforms:
        raise NoCiscoPolicyError('no cisco policy found in %s' % (
            header.target))

    self.policy = pol

  def __str__(self):
    target_header = []
    target = []
    obj_target = ObjectGroup()

    good_filters = ['extended', 'standard', 'object-group']

    # add the p4 tags
    p4_id = '%s%s' % ('$I', 'd:$')
    p4_date = '%s%s' % ('$Da', 'te:$')
    target_header.append('remark %s' % p4_id)
    target_header.append('remark %s' % p4_date)

    for header, terms in self.policy.filters:
      filter_options = header.FilterOptions('cisco')
      filter_name = header.FilterName('cisco')

      # extended is the most common filter type.
      filter_type = 'extended'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      # check if filter type is renderable
      if filter_type not in good_filters:
        raise UnsupportedCiscoAccessListError(
            'only access list types %s are supported' % str(good_filters))

      # if extended, validate filter name
      if filter_type is 'extended':
        if filter_name.isdigit():
          if 1 <= int(filter_name) <= 99:
            raise UnsupportedCiscoAccessListError(
                'access-lists between 1-99 are reservered for standard ACLs')

        # setup the access list names
        target.append('no ip access-list extended %s' % filter_name)
        target.append('ip access-list extended %s' % filter_name)

      # add a header comment if one exists
      for comment in header.comment:
        for line in comment.split('\n'):
          target.append('remark %s' % line)

      # if standard, validate filter name
      if filter_type == 'standard':
        if not filter_name.isdigit():
          raise UnsupportedCiscoAccessListError(
              'standard access lists must be numbered between 1 - 99')
        if filter_name.isdigit():
          if not 1 <= int(filter_name) <= 99:
            raise UnsupportedCiscoAccessListError(
                'standard access lists must be numbered between 1 - 99')
        # setup the access list names
        target.append('no ip access-list %s' % filter_name)

      if filter_type == 'object-group':
        obj_target.AddName(filter_name)
        target.append('no ip access-list extended %s' % filter_name)
        target.append('ip access-list extended %s' % filter_name)

      # now add the terms
      for term in terms:
        if filter_type == 'standard':
          target.append(str(TermStandard(term, filter_name)))
        elif filter_type == 'extended':
          target.append(str(Term(term)))
        elif filter_type == 'object-group':
          obj_target.AddTerm(term)
          target.append(str(ObjectGroupTerm(term, filter_name)))

      target.append('\n')

    if obj_target.valid:
      target = [str(obj_target)] + target

    # ensure that the header is always first
    target = target_header + target

    return '\n'.join(target)
