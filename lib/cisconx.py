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

"""Cisco NXOS generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ipaddr
from lib import aclgenerator
from lib import nacaddr
from lib import summarizer
from lib import cisco


class ObjectGroup(cisco.ObjectGroup):
  """Used for printing out the object group definitions.

  since the ports don't store the token name information, we have
  to fudge their names.  ports will be written out like

    object-group ip port <low_port>-<high_port>
      range <low-port> <high-port>
    exit

  where as the addressess can be written as

    object-group ip address first-term-source-address
      10 host 172.16.0.0
      20 172.20.0.0/16
    exit
  """

  def __str__(self):
    ret_str_addrs = ['\n']
    ret_str_ports = ['\n']
    # netgroups will contain two-tuples of group name string and family int.
    netgroups = set()
    ports = set()

    for obj_term in self.terms:
      # I don't have an easy way get the token name used in the pol file
      # w/o reading the pol file twice (with some other library) or doing
      # some other ugly hackery. Instead, the entire block of source and dest
      # addresses for a given term is given a unique, computable name which
      # is not related to the NETWORK.net token name.  that's what you get
      # for using cisco, which has decided to implement its own meta language.

      # Create network object-groups
      addr_type = ('source_address', 'destination_address')
      addr_family = (4, 6)
      term_addr_groups = obj_term.addr_groups
      term = obj_term.term

      seq_num = 0
      for source_or_dest in addr_type:
        for family in addr_family:
          addrs = term.GetAddressOfVersion(source_or_dest, family)
          if addrs:
            net_def_name = term_addr_groups.get(str(source_or_dest),
                                                addrs[0].parent_token)
            # We have addresses for this family and have not already seen it.
            if (net_def_name, family) not in netgroups:
              seq_num = 0
              netgroups.add((net_def_name, family))
              family_prefix = "ip" if family == 4 else "ipv6"

              # in case object group is created for the first time
              ret_str_addrs.append('object-group %s address %s' % (family_prefix, net_def_name))
              ret_str_addrs.append('exit\n')

              ret_str_addrs.append('no object-group %s address %s' % (family_prefix, net_def_name))
              ret_str_addrs.append('object-group %s address %s' % (family_prefix, net_def_name))
              for addr in addrs:
                seq_num += 10
                if addr.numhosts > 1:
                  ret_str_addrs.append(' %d %s/%s' % (seq_num, addr.ip, addr.prefixlen))
                else:
                  ret_str_addrs.append(' %d host %s' % (seq_num, addr.ip))
              ret_str_addrs.append('exit\n')

      # Create port object-groups
      for port in term.source_port + term.destination_port:
        if not port:
          continue
        port_key = '%s-%s' % (port[0], port[1])
        if port_key not in ports:
          seq_num = 10
          ports.add(port_key)
          # no ipv6 port-group for nxos
          family_prefix = "ip"

          # in case object group is being created for the first time
          ret_str_ports.append('object-group %s port %s' % (family_prefix, port_key))
          ret_str_ports.append('exit\n')

          ret_str_ports.append('no object-group %s port %s' % (family_prefix, port_key))
          ret_str_ports.append('object-group %s port %s' % (family_prefix, port_key))
          if port[0] != port[1]:
            ret_str_ports.append(' %d range %d %d' % (seq_num, port[0], port[1]))
          else:
            ret_str_ports.append(' %d eq %d' % (seq_num, port[0]))
          ret_str_ports.append('exit\n')

    ret_str_addrs.extend(ret_str_ports)

    return '\n'.join(ret_str_addrs)


class ObjectGroupTerm(cisco.ObjectGroupTerm):
  """An individual term of an object-group'd acl.

  Object Group acls are very similar to extended acls in their
  syntax except they use a meta language with address/service
  definitions.

  eg:

    permit tcp first-term-source-address 179-179 ANY

  where first-term-source-address, ANY and 179-179 are defined elsewhere
  in the acl.
  """
  # Protocols should be emitted as strings or portgroups fails for NXOS.
  _PROTO_INT = False

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self.platform not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self.platform in self.term.platform_exclude:
        return ''

    source_address_set = set()
    destination_address_set = set()
    ret_str = ['\n']
    ret_str.append(' remark %s' % self.term.name)
    comment_max_width = 70
    comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
    if comments and comments[0]:
      for comment in comments:
        ret_str.append(' remark %s' % str(comment))

    # Term verbatim output - this will skip over normal term creation
    # code by returning early.  Warnings provided in policy.py.
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == self._PLATFORM:
          ret_str.append(str(next_verbatim.value[1]))
        return '\n'.join(ret_str)

    # protocol
    if not self.term.protocol:
      protocol = ['ip']
    else:
      if self._PROTO_INT:
        # pylint: disable=g-long-lambda
        protocol = map(self.PROTO_MAP.get, self.term.protocol, self.term.protocol)
        # pylint: enable=g-long-lambda
      else:
        protocol = self.term.protocol

    # addresses
    source_address = self.term.source_address
    if not self.term.source_address:
      source_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]
    # get the summarized object group name from addr_groups to prevent
    # naming conflicts else use the parent token from ip address
    src_group_name = self.addr_groups.get('source_address',
                                          source_address[0].parent_token)
    source_address_set.add(src_group_name)

    destination_address = self.term.destination_address
    if not self.term.destination_address:
      destination_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]
    dest_group_name = self.addr_groups.get('destination_address',
                                           destination_address[0].parent_token)
    destination_address_set.add(dest_group_name)
    # ports
    source_port = [()]
    destination_port = [()]
    if self.term.source_port:
      source_port = self.term.source_port
    if self.term.destination_port:
      destination_port = self.term.destination_port

    # logging
    if self.term.logging:
      self.term.option.append('log')

    # icmp-types
    icmp_types = ['']
    if self.term.icmp_type:
      icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type,
                                           self.term.protocol,
                                           self.af)

    fixed_opts = {}
    for p in protocol:
      fixed_opts[p] = self._FixOptions(p, self.term.option)

    icmp_codes = ['']
    if self.term.icmp_code:
      icmp_codes = self.term.icmp_code

    for saddr in source_address_set:
      for daddr in destination_address_set:
        for sport in source_port:
          for dport in destination_port:
            for proto in protocol:
              opts = fixed_opts[proto]
              for icmp_type in icmp_types:
                for icmp_code in icmp_codes:
                  ret_str.append(
                    self._TermletToStr(
                        cisco._ACTION_TABLE.get(str(self.term.action[0])),
                        proto,
                        saddr,
                        sport,
                        daddr,
                        dport,
                        icmp_type,
                        icmp_code,
                        opts)
                  )
    return '\n'.join(ret_str)

  def _TermletToStr(self, action, proto, saddr, sport, daddr, dport,
                    icmp_type, icmp_code, option):
    """Take the various components and turn them into a cisco acl line.

    Args:
      action: str, action
      proto: str or int, protocol
      saddr: str, source address
      sport: str, the source port
      daddr: str, the destination address
      dport: str, the destination port
      icmp_type: icmp-type numeric specification (if any)
      option: list or none, optional, eg. 'logging' tokens.

    Returns:
      string of the cisco acl line, suitable for printing.

    """
    if saddr and saddr != 'any':
      saddr = 'addrgroup %s' % saddr
    if daddr and daddr != 'any':
      daddr = 'addrgroup %s' % daddr
      # fix ports
      # TODO(sjtarik): implement using portgroups named with non-integer values
    if sport:
      sport = 'portgroup %d-%d' % (sport[0], sport[1])
    else:
      sport = ''
    if dport:
      dport = 'portgroup %d-%d' % (dport[0], dport[1])
    else:
      dport = ''

    # icmpv6 is not a valid keyword for ios/nxos
    if proto == 'icmpv6':
      proto = 'icmp'

    # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
    icmp_type = str(icmp_type)
    all_elements = [action, str(proto), saddr, sport, daddr, dport, icmp_type,
                    icmp_code, ' '.join(option)]
    non_empty_elements = [x for x in all_elements if x]
    return ' ' + ' '.join(non_empty_elements)

  def _FixOptions(self, proto, option):
    """Returns a set of options suitable for the given protocol

    In practice this is only used to filter out 'established' for UDP.

    Args:
      proto: str or int, protocol
      option: list or none, optional, eg. 'logging' tokens.
    Returns:
      A list of options suitable for that protocol.
    """
    # Prevent UDP from appending 'established' to ACL line
    sane_options = list(option)
    if ((proto == self.PROTO_MAP['udp'] or proto == 'udp')
        and 'established' in sane_options):
      sane_options.remove('established')

    if 'tcp-established' in sane_options:
      sane_options.remove('tcp-established')
      sane_options.append('established')

    return sane_options


class Term(cisco.Term):
    _PLATFORM = 'cisconx'

    def __init__(self, term, af=4, proto_int=False, enable_dsmo=False,
                 term_remark=True, platform='cisconx'):
        super(Term, self).__init__(term, af, proto_int, enable_dsmo, term_remark, platform)

    def _GetIpString(self, addr):
        """Formats the address object for printing in the ACL.

        Args:
          addr: str or ipaddr, address
        Returns:
          An address string suitable for the ACL.
        """
        if type(addr) is nacaddr.IPv4 or type(addr) is ipaddr.IPv4Network:
            if addr.numhosts > 1:
                return '%s' % (addr.with_prefixlen)
            return 'host %s' % (addr.ip)
        if type(addr) is nacaddr.IPv6 or type(addr) is ipaddr.IPv6Network:
            if addr.numhosts > 1:
                return '%s' % (addr.with_prefixlen)
            return 'host %s' % (addr.ip)
        # TODO clarify the use case
        if type(addr) is tuple:
            return '%s %s' % summarizer.ToDottedQuad(addr, negate=False, nondsm=False)
        return addr


class CiscoNX(cisco.Cisco):
    """A cisco nxos policy object."""

    _PLATFORM = 'cisconx'
    _DEFAULT_PROTOCOL = 'ip'
    SUFFIX = '.nacl'

    # Protocols should not be emitted as numbers.
    _PROTO_INT = False

    def _AppendTargetByFilterType(self, filter_name, filter_type):
        """Takes in the filter name and type and appends headers.

        Args:
          filter_name: Name of the current filter
          filter_type: Type of current filter

        Returns:
          list of strings
        """
        target = []
        if filter_type == 'inet6':
            # in case access-list created for the first time
            target.append('ipv6 access-list %s' % filter_name)
            target.append('exit')

            target.append('no ipv6 access-list %s' % filter_name)
            target.append('ipv6 access-list %s' % filter_name)
        else:
            # in case access-list created for the first time
            target.append('ip access-list %s' % filter_name)
            target.append('exit')

            target.append('no ip access-list %s' % filter_name)
            target.append('ip access-list %s' % filter_name)
        return target

    def __str__(self):
        object_group_summary = ObjectGroup()
        target_header = []
        target = []
        # add the p4 tags
        target.extend(aclgenerator.AddRepositoryTags('! '))
        seq_num = 0

        for (header, filter_name, filter_list, terms, obj_target,
             v6_object) in self.cisco_policies:
            for filter_type in filter_list:
                new_target_lines = []
                if filter_type != 'object-group':
                  new_target_lines.extend(self._AppendTargetByFilterType(filter_name, filter_type))
                else:
                  object_group_af_type = 'inet'
                  if v6_object:
                    object_group_af_type = 'inet6'
                  new_target_lines.extend(
                    self._AppendTargetByFilterType(filter_name, object_group_af_type))

                if filter_type == 'object-group':
                    obj_target.AddName(filter_name)


                new_target_lines.extend(aclgenerator.AddRepositoryTags(
                    ' remark ', date=False, revision=False))

                # add a header comment if one exists
                for comment in header.comment:
                    for line in comment.split('\n'):
                        new_target_lines.append(' remark %s' % line)

                # now add the terms
                for term in terms:
                  term_str = str(term)
                  if term_str:
                    new_target_lines.append(term_str)

                seq_num = 0
                for new_line in new_target_lines:
                  new_line_sp = new_line.splitlines()
                  for sp in new_line_sp:
                    if sp.startswith((" permit", " remark", " deny")):
                      seq_num += 10
                      target.append(' ' + str(seq_num) + sp.rstrip())
                    else:
                      target.append(sp)

            if obj_target.valid:
              for oterm in obj_target.terms:
                object_group_summary.AddTerm(oterm)

            # ensure that the header is always first
            target = target_header + target
            target += ['', 'exit', '']

        if object_group_summary.valid:
          target = [str(object_group_summary)] + target
        return '\n'.join(target)

    def _TranslatePolicy(self, pol, exp_info):
      self.cisco_policies = []
      self.object_table = {}

      # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
      good_filters = ['extended', 'object-group', 'inet6', 'mixed']

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
          raise cisco.UnsupportedCiscoAccessListError(
            'access list type %s not supported by %s (good types: %s)' % (
              filter_type, self._PLATFORM, str(good_filters)))

        filter_list = [filter_type]
        if filter_type == 'mixed':
          # Loop through filter and generate output for inet and inet6 in sequence
          filter_list = ['extended', 'inet6']

        for next_filter in filter_list:
          new_terms = []
          for term in terms:
            term.name = self.FixTermLength(term.name)
            af = 'inet'
            if next_filter == 'inet6' or 'inet6' in filter_options:
              af = 'inet6'
            term = self.FixHighPorts(term, af=af)
            if not term:
              continue

            # render terms based on filter type
            if next_filter == 'extended':
              enable_dsmo = (len(filter_options) > 2 and
                             filter_options[2] == 'enable_dsmo')
              new_terms.append(
                Term(term, proto_int=self._PROTO_INT, enable_dsmo=enable_dsmo,
                     term_remark=self._TERM_REMARK, platform=self._PLATFORM))
            elif next_filter == 'object-group':
              group_name_alt = obj_target.GetAlternateNames(term,
                                                            self.object_table)
              obj_group_term = ObjectGroupTerm(term, filter_name,
                                               af=(4 if af == 'inet' else 6),
                                               addr_groups=group_name_alt)
              obj_target.AddTerm(obj_group_term)
              new_terms.append(obj_group_term)
            elif next_filter == 'inet6':
              new_terms.append(Term(term, 6, proto_int=self._PROTO_INT))

          # cisco requires different name for the v4 and v6 acls
          if filter_type == 'mixed' and next_filter == 'inet6':
            filter_name = 'ipv6-%s' % filter_name

          v6_group = filter_type == 'object-group' and 'inet6' in filter_options

          self.cisco_policies.append((header, filter_name, [next_filter],
                                      new_terms, obj_target, v6_group))
