# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Generic Windows security policy generator; requires subclassing."""

import datetime
import string

from absl import logging
from capirca.lib import aclgenerator
from capirca.lib import nacaddr


CMD_PREFIX = 'netsh ipsec static add '


class Term(aclgenerator.Term):
  """Generate generic windows policy terms."""

  _PLATFORM = 'windows'

  _COMMENT_FORMAT = string.Template(': $comment')

  # filter rules
  _ACTION_TABLE = {}

  def __init__(self, term, filter_name, filter_action, af='inet'):
    """Setup a new term.

    Args:
      term: A policy.Term object to represent in windows_ipsec.
      filter_name: The name of the filter chan to attach the term to.
      filter_action: The default action of the filter.
      af: Which address family ('inet' or 'inet6') to apply the term to.

    Raises:
      UnsupportedFilterError: Filter is not supported.
    """
    super().__init__(term)
    self.term = term  # term object
    self.filter = filter_name  # actual name of filter
    self.default_action = filter_action
    self.options = []
    self.af = af

    if af == 'inet6':
      self._all_ips = nacaddr.IPv6('::/0')
    else:
      self._all_ips = nacaddr.IPv4('0.0.0.0/0')

    self.term_name = '%s_%s' % (self.filter[:1], self.term.name)

  def __str__(self):
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    if self.term.platform:
      if self._PLATFORM not in self.term.platform:
        return ''
    if self.term.platform_exclude:
      if self._PLATFORM in self.term.platform_exclude:
        return ''

    ret_str = []

    # Don't render icmpv6 protocol terms under inet, or icmp under inet6
    if ((self.af == 'inet6' and 'icmp' in self.term.protocol) or
        (self.af == 'inet' and 'icmpv6' in self.term.protocol)):
      logging.debug(self.NO_AF_LOG_PROTO.substitute(term=self.term.name,
                                                    proto=self.term.protocol,
                                                    af=self.af))
      return ''

    # append comments to output
    ret_str.append(self._COMMENT_FORMAT.substitute(filter=self.filter,
                                                   term=self.term_name,
                                                   comment=self.term.comment))

    # if terms does not specify action, use filter default action
    if not self.term.action:
      self.term.action[0].value = self.default_action

    if self.term.action[0] == 'next':
      return ''

    if len(self.term.action) > 1:
      raise aclgenerator.UnsupportedFilterError('\n%s %s %s %s' % (
          'Multiple actions unsupported by', self._PLATFORM,
          '\nError in term:', self.term.name))

    # protocol
    if self.term.protocol:
      protocols = self.term.protocol
    else:
      protocols = ['any']

    # addresses
    src_addr = self.term.source_address
    if not src_addr:
      src_addr = [self._all_ips]

    dst_addr = self.term.destination_address
    if not dst_addr:
      dst_addr = [self._all_ips]

    if (self.term.source_address_exclude or
        self.term.destination_address_exclude):
      raise aclgenerator.UnsupportedFilterError('\n%s %s %s %s' % (
          'address exclusions unsupported by', self._PLATFORM,
          '\nError in term:', self.term.name))

    # ports = Map the ports in a straight list since multiports aren't supported
    (src_ports, dst_ports) = self._HandlePorts(self.term.source_port,
                                               self.term.destination_port)

    # The windows ipsec driver requires either 'tcp' or 'udp' to be specified
    # if a srcport or dstport is specified.  Fail if src or dst ports are
    # specified and of the protocols are not exactly one or both of 'tcp'
    # or 'udp'.
    if ((not set(protocols).issubset(set(['tcp', 'udp']))) and
        (len(src_ports) > 1 or len(dst_ports) > 1)):
      raise aclgenerator.UnsupportedFilterError('%s %s %s' % (
          '\n', self.term.name,
          'src or dst ports may only be specified with "tcp" and/or "udp".'))

    # icmp-types
    (icmp_types, protocols) = self._HandleIcmpTypes(self.term.icmp_type,
                                                    protocols)

    ret_str = []
    self._HandlePreRule(ret_str)
    self._CartesianProduct(src_addr, dst_addr, protocols, icmp_types, src_ports,
                           dst_ports, ret_str)
    self._HandlePreRule(ret_str)

    return '\n'.join(str(v) for v in ret_str if v)

  def _HandleIcmpTypes(self, icmp_types, protocols):
    """Perform implementation-specific icmp_type and protocol transforms.

    Note that icmp_types or protocols are passed as parameters in case they
    are to be munged prior to this function call, and may not be identical
    to self.term.* parameters.

    Args:
      icmp_types:  a list of icmp types, e.g., self.term.icmp_types
      protocols:  a list of protocols, e.g., self.term.protocols

    Returns:
      A pair of lists of (icmp_types, protocols)
    """
    return None, None

  def _HandlePorts(self, src_ports, dst_ports):
    """Perform implementation-specific port transforms.

    Note that icmp_types or protocols are passed as parameters in case they
    are to be munged prior to this function call, and may not be identical
    to self.term.* parameters.

    Args:
      src_ports:  list of source port range tuples, e.g., self.term.source_port
      dst_ports:  list of destination port range tuples

    Returns:
      A pair of lists of (icmp_types, protocols)
    """
    return None, None

  def _HandlePreRule(self, ret_str):
    """Perform any pre-cartesian product transforms on the ret_str array.

    Args:
      ret_str:  an array of strings that will eventually be joined to form
        the string output for the term.
    """
    pass

  def _CartesianProduct(self, src_addr, dst_addr, protocol, icmp_types,
                        src_ports, dst_ports, ret_str):
    """Perform any the appropriate cartesian product of the input parameters.

    Args:
      src_addr: a type(IP) list of the source addresses
      dst_addr: a type(IP) list of the destination addresses
      protocol: a string list of the protocols
      icmp_types: a numeric list of the icmp_types
      src_ports: a (start, end) list of the source ports
      dst_ports: a (start,end) list of the destination ports
      ret_str:  an array of strings that will eventually be joined to form
        the string output for the term.
    """
    pass

  def _HandlePostRule(self, ret_str):
    """Perform any port-cartesian product transforms on the ret_str array.

    Args:
      ret_str:  an array of strings that will eventually be joined to form
        the string output for the term.
    """
    pass


class WindowsGenerator(aclgenerator.ACLGenerator):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'windows'
  _DEFAULT_PROTOCOL = 'all'
  SUFFIX = '.bat'
  _RENDER_PREFIX = None
  _DEFAULT_ACTION = 'block'
  _TERM = Term

  _GOOD_AFS = ['inet', 'inet6']

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super()._BuildTokens()

    supported_tokens |= {'option'}
    supported_tokens -= {'verbatim'}

    supported_sub_tokens.update({'action': {'accept', 'deny'}})
    del supported_sub_tokens['option']
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Translate a policy from objects into strings."""
    self.windows_policies = []
    current_date = datetime.datetime.utcnow().date()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

    default_action = None
    good_default_actions = ['permit', 'block']
    good_options = []

    for header, terms in pol.filters:
      filter_type = None
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)[1:]
      filter_name = header.FilterName(self._PLATFORM)

      # ensure all options after the filter name are expected
      for opt in filter_options:
        if opt not in good_default_actions + self._GOOD_AFS + good_options:
          raise aclgenerator.UnsupportedTargetOptionError('%s %s %s %s' % (
              '\nUnsupported option found in', self._PLATFORM,
              'target definition:', opt))

      # Check for matching af
      for address_family in self._GOOD_AFS:
        if address_family in filter_options:
          # should not specify more than one AF in options
          if filter_type is not None:
            raise aclgenerator.UnsupportedFilterError('%s %s %s %s' % (
                '\nMay only specify one of', self._GOOD_AFS,
                'in filter options:', filter_options))
          filter_type = address_family
      if filter_type is None:
        filter_type = 'inet'

      # does this policy override the default filter actions?
      for next_target in header.target:
        if next_target.platform == self._PLATFORM:
          if len(next_target.options) > 1:
            for arg in next_target.options:
              if arg in good_default_actions:
                default_action = arg
      if default_action and default_action not in good_default_actions:
        raise aclgenerator.UnsupportedTargetOptionError('%s %s %s %s %s' % (
            '\nOnly', ', '.join(good_default_actions),
            'default filter action allowed;', default_action, 'used.'))

      # add the terms
      new_terms = []
      term_names = set()
      for term in terms:
        if term.name in term_names:
          raise aclgenerator.DuplicateTermError(
              'You have a duplicate term: %s' % term.name)
        term_names.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info('INFO: Term %s in policy %s expires '
                         'in less than two weeks.', term.name, filter_name)
          if term.expiration <= current_date:
            logging.warning('WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.', term.name, filter_name)
            continue
        if 'established' in term.option or 'tcp-established' in term.option:
          continue
        new_terms.append(self._TERM(term, filter_name, default_action,
                                    filter_type))

      self.windows_policies.append((header, filter_name, filter_type,
                                    default_action, new_terms))

  def __str__(self):
    target = []
    pretty_platform = '%s%s' % (self._PLATFORM[0].upper(), self._PLATFORM[1:])

    if self._RENDER_PREFIX:
      target.append(self._RENDER_PREFIX)

    for header, _, filter_type, default_action, terms in self.windows_policies:
      # Add comments for this filter
      target.append(': %s %s Policy' % (pretty_platform,
                                        header.FilterName(self._PLATFORM)))

      self._HandlePolicyHeader(header, target)

      # reformat long text comments, if needed
      comments = aclgenerator.WrapWords(header.comment, 70)
      if comments and comments[0]:
        for line in comments:
          target.append(': %s' % line)
        target.append(':')
      # add the p4 tags
      target.extend(aclgenerator.AddRepositoryTags(': '))
      target.append(': ' + filter_type)

      if default_action:
        raise aclgenerator.UnsupportedTargetOptionError(
            'Windows generator does not support default actions')

      # add the terms
      for term in terms:
        term_str = str(term)
        if term_str:
          target.append(term_str)
          self._HandleTermFooter(header, term, target)

    target.append('')
    return '\n'.join(target)

  def _HandlePolicyHeader(self, header, target):
    pass

  def _HandleTermFooter(self, header, term, target):
    pass
