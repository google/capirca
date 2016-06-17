# Copyright 2007 Google Inc. All Rights Reserved.
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

"""Squid generator."""

import nacaddr

import aclgenerator


class Term(aclgenerator.Term):
  """Generate Squid policy terms."""

  # Validate that term does not contain any fields we do not
  # support.  This prevents us from thinking that our output is
  # correct in cases where we've omitted fields from term.
  _PLATFORM = 'squid'
  _ACTION_TABLE = {
    'accept': 'allow',
    'deny': 'deny',
  }
  _SUPPORTED_PROTOS = [
    'tcp',
    'all',
  ]

  def __init__(self, term, filter_name, trackstate, filter_action, af='inet'):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in squid.
      filter_name: The name of the filter chan to attach the term to.
      trackstate: Specifies if conntrack should be used for new
            connections
      filter_action: The default action of the filter.
      af: Which address family ('inet' or 'inet6') to apply the term to.

    Raises:
      UnsupportedFilterError: Filter is not supported.
    """
    self.trackstate = trackstate
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.default_action = filter_action
    self.options = []
    self.af = af
    self.data = {}

    if af == 'inet6':
      self._all_ips = nacaddr.IPv6('::/0')
    else:
      self._all_ips = nacaddr.IPv4('0.0.0.0/0')

    self.term_name = '%s_%s' % (self.filter[:1], self.term.name)

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    d = {}
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    ret_str = []

    # Term verbatim output - this will skip over most normal term
    # creation code by returning early. Warnings provided in policy.py
    if self.term.verbatim:
      for next_verbatim in self.term.verbatim:
        if next_verbatim.value[0] == self._PLATFORM:
          ret_str.append(str(next_verbatim.value[1]))
      return '\n'.join(ret_str)

    # unsupported filters
    if self.term.ether_type:
      raise UnsupportedFilterError('\n%s %s %s %s' % (
          'ether_type unsupported by', self._PLATFORM,
          '\nError in term', self.term.name))
    if self.term.address:
      raise UnsupportedFilterError('\n%s %s %s %s %s' % (
          'address unsupported by', self._PLATFORM,
          '- specify source or dest', '\nError in term:',
          self.term.name))
    if self.term.port:
      raise UnsupportedFilterError('\n%s %s %s %s %s' % (
          'port unsupported by', self._PLATFORM,
          '- specify source or dest', '\nError in term:',
          self.term.name))
    if self.term.source_prefix or self.term.destination_prefix:
      raise UnsupportedFilterError('prefixes are not supported by squid'
                     '\nError in term: %s' % self.term.name)

    if self.term.owner:
      self.term.comment.append('Owner: %s' % self.term.owner)
    if self.term.orig_name != self.term.name:
      self.term.comment.append('Original name: %s' % self.term.orig_name)

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action
    action = self._ACTION_TABLE[str(self.term.action[0])]

    # Determine the protocol at play
    if self.term.protocol:
      protocol = self.term.protocol[0]
    else:
      protocol = 'all'

    if protocol not in self._SUPPORTED_PROTOS:
      # Silently skip over unsupported protocols -
      # squid only supports tcp/all
      return ('# skipped %s due to protocol %s not being supported' %
          (self.term.name, protocol))
    if self.term.fragment_offset:
      # silently skip fragment offsets - not something we can handle
      return ('# skipped %s as fragment offset is not supported' %
          (self.term.name))

    (src_name, src_list), (dst_name, dst_list) = self._CalculateAddresses(
      self.term.source_address,
      self.term.source_address_exclude,
      self.term.destination_address,
      self.term.destination_address_exclude,
    )

    if src_list:
      # add source networks
      d[src_name] = [str(net) for net in src_list]
      src_nets = ['acl %s src %s' % (src_name, net) for net in src_list]
      ret_str.extend(src_nets)

    if dst_list:
      # add destination networks
      d[dst_name] = [str(net) for net in dst_list]
      dst_nets = ['acl %s dst %s' % (dst_name, net) for net in dst_list]
      ret_str.extend(dst_nets)

    # see if we need to dump in source ports
    if self.term.source_port:
      src_port_name, src_port_list = self._CalculatePorts(
        self.term.source_port,
        direction='src')
      d[src_port_name] = src_port_list
      source_ports = ['acl %s port %s' % (src_port_name, port)
              for port in src_port_list]
      ret_str.extend(source_ports)

    # check destination ports
    if self.term.destination_port:
      dst_port_name, dst_port_list = self._CalculatePorts(
        self.term.destination_port,
        direction='dst')
      d[dst_port_name] = dst_port_list
      dest_ports = ['acl %s port %s' % (dst_port_name, port)
              for port in dst_port_list]
      ret_str.extend(dest_ports)

    # emit the permission
    rule = 'http_access %s %s' % (action, ' '.join(d.keys() or ['all']))
    d['rule'] = {
      'action': action,
      'rule_acls': d.keys() or ['all'],
    }
    if self.term.comment:
      d['rule']['comment'] = ';'.join(self.term.comment)
    ret_str.append(rule)
    self.data = d

    return '\n'.join(str(v) for v in ret_str if v is not '')

  def _CalculatePorts(self, ports, direction):
    """
    Provide a squid-consumable name and port listing for input ports.

      Args:
        ports - the list of ports (list of tuples or ints)
        direction - should be 'src' or 'dst'

      Returns:
        (aclname, [int|str, ...])

      Example return:
        ('http-dst-ports', [80, 443, 8080, '8090-8099', 8443])
    """
    name = self._GenerateShortName(self.term.name, '%s-port' % direction)

    def sanitize(x):
      if not isinstance(x, tuple):
        return x
      from_p, to_p = x
      if from_p == to_p:
        return from_p
      return '%s-%s' % (from_p, to_p)

    return (name, [sanitize(p) for p in ports])

  def _CalculateAddresses(self, src_addr_list, src_ex_addr_list,
              dst_addr_list, dst_ex_addr_list):
    """
    For a given set of source/destination networks, provide squid-consumable
    tuples of (shortname, [networks...]). If no networks are provided for
    either the source or destination - the networks list will be Falsey.

      Args:
        src_addr_list - source network list
        src_ex_addr_list - source exclusion network list
        dst_addr_list - destination network list
        dst_ex_addr_list - destination network list

      Returns:
        ((source_name, [source_networks]), (dest_name, [dest_networks]))

      Example:
        (('blockall-src', None), ('blockall-dst', ['0.0.0.0/0']))
    """
    if not src_addr_list:
      src_addr_list = [self._all_ips]
    else:
      src_addr_list = [src_addr for src_addr in src_addr_list if
               src_addr.version == self.AF_MAP[self.af]]

    if src_ex_addr_list:
      src_ex_addr_list = [src_ex_addr for src_ex_addr in src_ex_addr_list
                if src_ex_addr.version == self.AF_MAP[self.af]]
      src_addr_list = nacaddr.ExcludeAddrs(src_addr_list,
                         src_ex_addr_list)

    if src_addr_list == [self._all_ips]:
      src_addr_list = None

    source = (self._GenerateShortName(self.term.name, 'src'), src_addr_list)

    if not dst_addr_list:
      dst_addr_list = [self._all_ips]
    else:
      dst_addr_list = [dst_addr for dst_addr in dst_addr_list if
               dst_addr.version == self.AF_MAP[self.af]]

    if dst_ex_addr_list:
      dst_ex_addr_list = [dst_ex_addr for dst_ex_addr in dst_ex_addr_list
                if dst_ex_addr.version == self.AF_MAP[self.af]]
      dst_addr_list = nacaddr.ExcludeAddrs(dst_addr_list,
                         dst_ex_addr_list)

    if dst_addr_list == [self._all_ips]:
      dst_addr_list = None

    dest = (self._GenerateShortName(self.term.name, 'dst'), dst_addr_list)

    return (source, dest)

  def _GenerateShortName(self, term_name, suffix):
    return '%s-%s' % (term_name, suffix)


class Squid(aclgenerator.ACLGenerator):
  """Generates filters and terms from provided policy object."""

  SUFFIX = '.squid.conf'
  _PLATFORM = 'squid'
  _DEFAULT_PROTOCOL = 'all'
  _RENDER_PREFIX = None
  _RENDER_SUFFIX = None
  _DEFAULTACTION_FORMAT = '-P %s %s'
  _DEFAULT_ACTION = 'DROP'
  _TERM = Term
  _TERM_MAX_LENGTH = 22  # 31 - 5 (-port) - 4 (-direction)
  _OPTIONAL_SUPPORTED_KEYWORDS = set([
    'counter',
    'destination_interface',
    'destination_prefix',  # skips these terms
    'expiration',
    'fragment_offset',
    'logging',
    'owner',
    'packet_length',
    'policer',             # safely ignored
    'qos',
    'routing_instance',    # safe to skip
    'source_interface',
    'source_prefix',       # skips these terms
  ])

  def _TranslatePolicy(self, pol, exp_info):
    """Translate a policy from objects into strings.

      pol: policy.Policy object
      exp_info: int, weeks in advance to notify a term will expire.

    """
    self.squid_policies = []

    default_action = None
    good_afs = ['inet', 'inet6']
    good_options = [
      'hashterms',
      'truncateterms',
      'abbreviateterms',
      'reverseflow',
    ]
    all_protocols_stateful = True

    for header, terms in pol.filters:
      filter_type = None
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)[1:]
      filter_name = header.FilterName(self._PLATFORM)

      # ensure all options after the filter name are expected
      for opt in filter_options:
        if opt not in good_afs + good_options:
          raise UnsupportedTargetOption('%s %s %s %s' % (
              '\nUnsupported option found in', self._PLATFORM,
              'target definition:', opt))

      # Check for matching af
      for address_family in good_afs:
        if address_family in filter_options:
          # should not specify more than one AF in options
          if filter_type is not None:
            raise UnsupportedFilterError('%s %s %s %s' % (
                '\nMay only specify one of',
                good_afs,
                'in filter options:',
                filter_options))
          filter_type = address_family
      if filter_type is None:
        filter_type = 'inet'

      # add the terms
      new_terms = []
      term_names = set()
      for term in terms:
        if 'next' in term.action:
          continue
        term.orig_name = term.name
        term.name = self.FixTermLength(
          term.name,
          'abbreviateterms' in filter_options,
          'truncateterms' in filter_options,
          'hashterms' in filter_options,
        )
        if term.name in term_names:
          raise aclgenerator.DuplicateTermError(
              'You have a duplicate term: %s' % term.name)
        term_names.add(term.name)

        if term.expiration:
          self.CheckAndWarnForExpiration(term.name,
                           filter_name,
                           pol,
                           term.expiration,
                           exp_info)

        term = self.FixHighPorts(
          term,
          af=filter_type,
          all_protocols_stateful=all_protocols_stateful,
        )
        if not term:
          continue

        if 'reverseflow' in filter_options:
          # holy hack - if we reverse the flow we need to
          # swap all of the source/destination attributes
          swap_attrs = [
            ('source_address', 'destination_address'),
            ('source_address_exclude',
              'destination_address_exclude'),
            ('source_port', 'destination_port'),
            ('source_interface', 'destination_interface'),
          ]
          for from_var, to_var in swap_attrs:
            # store both from/to variables
            fv = getattr(term, from_var)
            tv = getattr(term, to_var)
            # now swap them in reverse place
            setattr(term, to_var, fv)
            setattr(term, from_var, tv)

        new_terms.append(self._TERM(term, filter_name,
                 all_protocols_stateful,
                 default_action, filter_type))

      self.squid_policies.append((header, filter_name, filter_type,
                    default_action, new_terms))

  def __str__(self):
    """
    Render the actual policy.
    """

    target = []
    pretty_platform = '%s%s' % (self._PLATFORM[0].upper(),
                  self._PLATFORM[1:])

    if self._RENDER_PREFIX:
      target.append(self._RENDER_PREFIX)

    for (header, filter_name, filter_type, default_action, terms) \
        in self.squid_policies:
      # Add comments for this filter
      target.append('# %s %s Policy' % (pretty_platform,
              header.FilterName(self._PLATFORM)))

      # reformat long text comments, if needed
      comments = aclgenerator.WrapWords(header.comment, 70)
      if comments and comments[0]:
        for line in comments:
          target.append('# %s' % line)
        target.append('#')
      # add the p4 tags
      target.extend(aclgenerator.AddRepositoryTags('# '))
      target.append('# ' + filter_type)

      if default_action:
        target.append(self._DEFAULTACTION_FORMAT %
                (filter_name, default_action))
      # add the terms
      for term in terms:
        term_str = str(term)
        if term_str:
          target.append(term_str)

    if self._RENDER_SUFFIX:
      target.append(self._RENDER_SUFFIX)

    target.append('')
    return '\n'.join(target)


class Error(Exception):
  """Base error class."""


class UnsupportedFilterError(Error):
  """Raised when we see an inappropriate filter."""


class UnsupportedTargetOption(Error):
  """Raised when a filter has an impermissible default action specified."""
