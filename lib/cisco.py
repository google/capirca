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

"""Cisco generator."""

__author__ = 'pmoody@google.com (Peter Moody)'
__author__ = 'watson@google.com (Tony Watson)'

import datetime
import logging
import re

from third_party import ipaddr
import aclgenerator
import nacaddr


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


class TermStandard(object):
  """A single standard ACL Term."""

  def __init__(self, term, filter_name):
    self.term = term
    self.filter_name = filter_name
    self.options = []
    self.logstring = ''
    # sanity checking for standard acls
    if self.term.protocol:
      raise StandardAclTermError(
          'Standard ACLs cannot specify protocols')
    if self.term.icmp_type:
      raise StandardAclTermError(
          'ICMP Type specifications are not permissible in standard ACLs')
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
      logging.warn(
          'WARNING: Standard ACL logging is set in filter %s, term %s and '
          'may not implemented on all IOS versions', self.filter_name,
          self.term.name)
      self.logstring = ' log'

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'cisco' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'cisco' in self.term.platform_exclude:
        return ''

    ret_str = []

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == 'cisco':
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    v4_addresses = [x for x in self.term.address if type(x) != nacaddr.IPv6]
    if self.filter_name.isdigit():
      ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                   self.term.name))

      comment_max_width = 70
      comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
      if comments and comments[0]:
        for comment in comments:
          ret_str.append('access-list %s remark %s' % (self.filter_name,
                                                       comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append('access-list %s %s %s%s' % (self.filter_name,
                                                       action,
                                                       addr.ip,
                                                       self.logstring))
          else:
            ret_str.append('access-list %s %s %s %s%s' % (self.filter_name,
                                                          action,
                                                          addr.network,
                                                          addr.hostmask,
                                                          self.logstring))
      else:
        ret_str.append('access-list %s %s %s%s' % (self.filter_name, action,
                                                   'any', self.logstring))

    else:
      ret_str.append('remark ' + self.term.name)
      comment_max_width = 70
      comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
      if comments and comments[0]:
        for comment in comments:
          ret_str.append('remark ' + str(comment))

      action = _ACTION_TABLE.get(str(self.term.action[0]))
      if v4_addresses:
        for addr in v4_addresses:
          if addr.prefixlen == 32:
            ret_str.append(' %s %s%s' % (action, addr.ip, self.logstring))
          else:
            ret_str.append(' %s %s %s%s' % (action, addr.network,
                                            addr.hostmask, self.logstring))
      else:
        ret_str.append(' %s %s%s' % (action, 'any', self.logstring))

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
    # pylint: disable-msg=C6411
    return len(self.terms) > 0
    # pylint: enable-msg=C6411

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
      if saddrs and saddrs[0].parent_token not in addresses:
        addresses[saddrs[0].parent_token] = True
        ret_str.append('object-group ip address %s' % saddrs[0].parent_token)
        for addr in saddrs:
          ret_str.append(' %s %s' % (addr.ip, addr.netmask))
        ret_str.append('exit\n')

      # destination address
      daddrs = term.GetAddressOfVersion('destination_address', 4)
      # check to see if we've already seen this address
      if daddrs and daddrs[0].parent_token not in addresses:
        addresses[daddrs[0].parent_token] = True
        ret_str.append('object-group ip address %s' % daddrs[0].parent_token)
        for addr in term.GetAddressOfVersion('destination_address', 4):
          ret_str.append(' %s %s' % (addr.ip, addr.netmask))
        ret_str.append('exit\n')

      # source port
      for port in term.source_port + term.destination_port:
        if not port:
          continue
        port_key = '%s-%s' % (port[0], port[1])
        if port_key not in ports.keys():
          ports[port_key] = True
          ret_str.append('object-group ip port %s' % port_key)
          if port[0] != port[1]:
            ret_str.append(' range %d %d' % (port[0], port[1]))
          else:
            ret_str.append(' eq %d' % port[0])
          ret_str.append('exit\n')

    return '\n'.join(ret_str)


class ObjectGroupTerm(aclgenerator.Term):
  """An individual term of an object-group'd acl.

  Object Group acls are very similar to extended acls in their
  syntax except they use a meta language with address/service
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
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'cisco' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'cisco' in self.term.platform_exclude:
        return ''

    source_address_dict = {}
    destination_address_dict = {}

    ret_str = ['\n']
    ret_str.append('remark %s' % self.term.name)
    comment_max_width = 70
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      for comment in comments:
        ret_str.append('remark %s' % str(comment))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == 'cisco':
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      protocol = ['ip']
    else:
      # pylint: disable-msg=C6402
      protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)
      # pylint: enable-msg=C6402

    # addresses
    source_address = self.term.source_address
    if not self.term.source_address:
      source_address = [nacaddr.IPv4('0.0.0.0/0', token='ANY')]
    source_address_dict[source_address[0].parent_token] = True

    destination_address = self.term.destination_address
    if not self.term.destination_address:
      destination_address = [nacaddr.IPv4('0.0.0.0/0', token='ANY')]
    destination_address_dict[destination_address[0].parent_token] = True
    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    for saddr in source_address:
      for daddr in destination_address:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              ret_str.append(
                  self._TermletToStr(_ACTION_TABLE.get(str(
                      self.term.action[0])), proto, saddr, sport, daddr, dport))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport):
    """Output a portion of a cisco term/filter only, based on the 5-tuple."""
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


class Term(aclgenerator.Term):
  """A single ACL Term."""

  def __init__(self, term, af=4):
    self.term = term
    self.options = []
    # Our caller should have already verified the address family.
    assert af in (4, 6)
    self.af = af
    self.text_af = self.AF_MAP_BY_NUMBER[self.af]

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if 'cisco' not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if 'cisco' in self.term.platform_exclude:
        return ''

    ret_str = ['\n']

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 6 and 'icmp' in self.term.protocol) or
        (self.af == 4 and 'icmpv6' in self.term.protocol)):
      ret_str.append('remark Term %s' % self.term.name)
      ret_str.append('remark not rendered due to protocol/AF mismatch.')
      return '\n'.join(ret_str)

    ret_str.append('remark ' + self.term.name)
    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    for comment in self.term.comment:
      for line in comment.split('\n'):
        ret_str.append('remark ' + str(line)[:100])

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == 'cisco':
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      if self.af == 6:
        protocol = ['ipv6']
      else:
        protocol = ['ip']
    else:
      # pylint: disable-msg=C6402
      protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)
      # pylint: disable-msg=C6402

    # source address
    if self.term.source_address:
      source_address = self.term.GetAddressOfVersion('source_address', self.af)
      source_address_exclude = self.term.GetAddressOfVersion(
          'source_address_exclude', self.af)
      if source_address_exclude:
        source_address = nacaddr.ExcludeAddrs(
            source_address,
            source_address_exclude)
      if not source_address:
        logging.warn(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                    direction='source',
                                                    af=self.text_af))
        return ''
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
      if not destination_address:
        logging.warn(self.NO_AF_LOG_ADDR.substitute(term=self.term.name,
                                                    direction='destination',
                                                    af=self.text_af))
        return ''
    else:
      # destination address not set
      destination_address = ['any']

    # options
    opts = [str(x) for x in self.term.option]
    if self.PROTO_MAP['tcp'] in protocol and ('tcp-established' in opts or
                                              'established' in opts):
      self.options.extend(['established'])

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
                ret_str.extend(self._TermletToStr(
                    _ACTION_TABLE.get(str(self.term.action[0])),
                    proto,
                    saddr,
                    sport,
                    daddr,
                    dport,
                    icmp_type,
                    self.options))

    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport,
                    icmp_type, option):
    """Take the various compenents and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str, protocl
      saddr: str or ipaddr, source address
      sport: str list or none, the source port
      daddr: str or ipaddr, the destination address
      dport: str list or none, the destination port
      icmp_type: icmp-type numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.

    Raises:
      UnsupportedCiscoAccessListError: When unknown icmp-types specified
    """
    # inet4
    if type(saddr) is nacaddr.IPv4 or type(saddr) is ipaddr.IPv4Network:
      if saddr.numhosts > 1:
        saddr = '%s %s' % (saddr.ip, saddr.hostmask)
      else:
        saddr = 'host %s' % (saddr.ip)
    if type(daddr) is nacaddr.IPv4 or type(daddr) is ipaddr.IPv4Network:
      if daddr.numhosts > 1:
        daddr = '%s %s' % (daddr.ip, daddr.hostmask)
      else:
        daddr = 'host %s' % (daddr.ip)
    # inet6
    if type(saddr) is nacaddr.IPv6 or type(saddr) is ipaddr.IPv6Network:
      if saddr.numhosts > 1:
        saddr = '%s' % (saddr.with_prefixlen)
      else:
        saddr = 'host %s' % (saddr.ip)
    if type(daddr) is nacaddr.IPv6 or type(daddr) is ipaddr.IPv6Network:
      if daddr.numhosts > 1:
        daddr = '%s' % (daddr.with_prefixlen)
      else:
        daddr = 'host %s' % (daddr.ip)

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

    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if proto == self.PROTO_MAP['udp'] and 'established' in sane_options:
      sane_options.remove('established')
    ret_lines = []

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(icmp_type)
    if icmp_type:
      ret_lines.append(' %s %s %s %s %s %s %s %s' % (action, proto, saddr,
                                                     sport, daddr, dport,
                                                     icmp_type,
                                                     ' '.join(sane_options)
                                                    ))
    else:
      ret_lines.append(' %s %s %s %s %s %s %s' % (action, proto, saddr,
                                                  sport, daddr, dport,
                                                  ' '.join(sane_options)
                                                 ))

    # remove any trailing spaces and replace multiple spaces with singles
    stripped_ret_lines = [re.sub(r'\s+', ' ', x).rstrip() for x in ret_lines]
    return stripped_ret_lines


class Cisco(aclgenerator.ACLGenerator):
  """A cisco policy object."""

  _PLATFORM = 'cisco'
  _DEFAULT_PROTOCOL = 'ip'
  _SUFFIX = '.acl'

  _OPTIONAL_SUPPORTED_KEYWORDS = set(['address',
                                      'counter',
                                      'expiration',
                                      'logging',
                                      'loss_priority',
                                      'owner',
                                      'policer',
                                      'port',
                                      'qos',
                                      'routing_instance',
                                     ])

  def _TranslatePolicy(self, pol, exp_info):
    self.cisco_policies = []
    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
    good_filters = ['extended', 'standard', 'object-group', 'inet6',
                    'mixed']

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      obj_target = ObjectGroup()

      filter_options = header.FilterOptions(self._PLATFORM)
      filter_name = header.FilterName(self._PLATFORM)

      # extended is the most common filter type.
      filter_type = 'extended'
      if len(filter_options) > 1:
        filter_type = filter_options[1]

      # check if filter type is renderable
      if filter_type not in good_filters:
        raise UnsupportedCiscoAccessListError(
            'access list type %s not supported by %s (good types: %s)' % (
                filter_type, self._PLATFORM, str(good_filters)))

      filter_list = [filter_type]
      if filter_type == 'mixed':
        # Loop through filter and generate output for inet and inet6 in sequence
        filter_list = ['extended', 'inet6']

      for next_filter in filter_list:
        if next_filter == 'extended':
          try:
            if int(filter_name) in range(1, 100) + range(1300, 2000):
              raise UnsupportedCiscoAccessListError(
                  'Access lists between 1-99 and 1300-1999 are reserved for '
                  'standard ACLs')
          except ValueError:
            # Extended access list names do not have to be numbers.
            pass
        if next_filter == 'standard':
          try:
            if int(filter_name) not in range(1, 100) + range(1300, 2000):
              raise UnsupportedCiscoAccessListError(
                  'Standard access lists must be numeric in the range of 1-99'
                  ' or 1300-1999.')
          except ValueError:
            # Standard access list names do not have to be numbers either.
            pass

        new_terms = []
        for term in terms:
          term.name = self.FixTermLength(term.name)
          af = 'inet'
          if next_filter == 'inet6':
            af = 'inet6'
          term = self.FixHighPorts(term, af=af)
          if not term:
            continue

          if term.expiration:
            if term.expiration <= exp_info_date:
              logging.info('INFO: Term %s in policy %s expires '
                           'in less than two weeks.', term.name, filter_name)
            if term.expiration <= current_date:
              logging.warn('WARNING: Term %s in policy %s is expired and '
                           'will not be rendered.', term.name, filter_name)
              continue

          # render terms based on filter type
          if next_filter == 'standard':
            # keep track of sequence numbers across terms
            new_terms.append(TermStandard(term, filter_name))
          elif next_filter == 'extended':
            new_terms.append(Term(term))
          elif next_filter == 'object-group':
            obj_target.AddTerm(term)
            new_terms.append(ObjectGroupTerm(term, filter_name))
          elif next_filter == 'inet6':
            new_terms.append(Term(term, 6))

        self.cisco_policies.append((header, filter_name, [next_filter],
                                    new_terms, obj_target))

  def __str__(self):
    target_header = []
    target = []

    # add the p4 tags
    target.extend(aclgenerator.AddRepositoryTags('! '))

    for (header, filter_name, filter_list, terms, obj_target
        ) in self.cisco_policies:
      for filter_type in filter_list:
        if filter_type == 'standard':
          if filter_name.isdigit():
            target.append('no access-list %s' % filter_name)
          else:
            target.append('no ip access-list standard %s' % filter_name)
            target.append('ip access-list standard %s' % filter_name)
        elif filter_type == 'extended':
          target.append('no ip access-list extended %s' % filter_name)
          target.append('ip access-list extended %s' % filter_name)
        elif filter_type == 'object-group':
          obj_target.AddName(filter_name)
          target.append('no ip access-list extended %s' % filter_name)
          target.append('ip access-list extended %s' % filter_name)
        elif filter_type == 'inet6':
          target.append('no ipv6 access-list %s' % filter_name)
          target.append('ipv6 access-list %s' % filter_name)
        else:
          raise UnsupportedCiscoAccessListError(
              'access list type %s not supported by %s' % (
                  filter_type, self._PLATFORM))

        # Add the Perforce Id/Date tags, these must come after
        # remove/re-create of the filter, otherwise config mode doesn't
        # know where to place these remarks in the configuration.
        if filter_name.isdigit():
          target.extend(aclgenerator.AddRepositoryTags('access-list %s remark '
                                                       % filter_name))
        else:
          target.extend(aclgenerator.AddRepositoryTags('remark '))

        # add a header comment if one exists
        for comment in header.comment:
          for line in comment.split('\n'):
            target.append('remark %s' % line)

        # now add the terms
        for term in terms:
          term_str = str(term)
          if term_str:
            target.append(term_str)
        target.append('\n')

      if obj_target.valid:
        target = [str(obj_target)] + target
      # ensure that the header is always first
      target = target_header + target
    target += ['end', '']
    return '\n'.join(target)
