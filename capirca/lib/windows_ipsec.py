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
"""Windows IP security policy generator."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

# pylint: disable=g-importing-member
from string import Template

from capirca.lib import aclgenerator
from capirca.lib import windows
from six.moves import range
from absl import logging


class Term(windows.Term):
  """Generate windows IP security policy terms."""

  _PLATFORM = 'windows_ipsec'
  CMD_PREFIX = 'netsh ipsec static add '

  # Windows IPSec Policy (which actually isn't limit to IPSec proper, as you
  # might expect) is structured such that you create:
  #   * One policy (more can be defined, but only one active)
  #   * One or more filter lists, which is similar to an IP chain (but does not
  #     support action:: next)
  #   * A filter, which is the matcher portion of a term
  #   * A filteraction, which is the action to perform when a a filter is
  #     matched.  Not that the filter action does not support logging, logging
  #     is associated with a auditpol filterlist.
  #   * a rule, which links a policy, filter list, and filter action.

  # Logging:
  # auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable
  #   /failure:enable
  # auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
  # auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
  # auditpol /set /subcategory:"IPsec Quick Mode" /success:enable
  #   /failure:enable
  # auditpol /set /subcategory:"IPsec Extended Mode" /success:enable
  #   /failure:enable

  _MASK_ATOM = Template('${dir}mask=${mask}')
  _ADDR_ATOM = Template('${dir}addr=${addr} ${mask}')
  _PROTO_ATOM = Template('protocol=${protocol}')
  _PORT_ATOM = Template('${dir}port=${port}')

  # ipsec is not stateful, we need mirrored=yes to get responses:
  _FILTER_FORMAT = Template('filter filterlist=${name} mirrored=yes '
                            '${atoms}')
  _FILTERACTION_FORMAT = Template('filteraction name=${name} '
                                  'action=${action}')
  _FILTERLIST_FORMAT = Template('filterlist name=$name ')
  _RULE_FORMAT = Template('rule name=$name policy=$policy '
                          'filterlist=$filterlist '
                          'filteraction=$filteraction ')
  _COMMENT_FORMAT = Template(': $comment')
  _LIST_SUFFIX = '-list'
  _ACTION_SUFFIX = '-action'

  # filter rules
  _ACTION_TABLE = {
      'accept': 'permit',
      'deny': 'block',
      'reject': 'block',
      }

  def _HandleIcmpTypes(self, icmp_types, protocols):
    if icmp_types:
      raise aclgenerator.UnsupportedFilterError('\n%s %s %s %s' % (
          'icmp types unsupported by', self._PLATFORM,
          '\nError in term:', self.term.name))
    return ([''], protocols)

  def _HandlePorts(self, src_ports, dst_ports):
    # ports = Map the ports in a straight list since multiports aren't supported
    return (self._CollapsePortTuples(src_ports),
            self._CollapsePortTuples(dst_ports))

  def _HandlePreRule(self, ret_str):
    ret_str.append(self._ComposeFilterList())
    ret_str.append(self._ComposeFilterAction(
        self._ACTION_TABLE[self.term.action[0]]))

  def _CartesianProduct(self, src_addr, dst_addr, protocol, unused_icmp_types,
                        src_port, dst_port, ret_str):
    # yup, the full cartesian product... this makes me cry on the inside.
    for saddr in src_addr:
      if saddr.version != 4:
        logging.warn('WARNING: term contains a non IPv4 address %s, '
                     'ignoring element of term %s.', saddr, self.term_name)
        continue

      for daddr in dst_addr:
        if daddr.version != 4:
          logging.warn('WARNING: term contains a non IPv4 address %s, '
                       'ignoring element of term %s.', daddr, self.term_name)
          continue

        for proto in protocol:
          for sport in src_port:
            for dport in dst_port:
              ret_str.append(self._ComposeFilter(
                  saddr.ip, daddr.ip, proto, saddr.prefixlen,
                  daddr.prefixlen, sport, dport))

  def _CollapsePortTuples(self, port_tuples):
    ports = ['']
    for tpl in port_tuples:
      if tpl:
        (port_start, port_end) = tpl
        ports = list(range(port_start, port_end+1))
    return ports

  def _ComposeFilterList(self):
    return (self.CMD_PREFIX +
            self._FILTERLIST_FORMAT.substitute(
                name=self.term_name + self._LIST_SUFFIX))

  def _ComposeFilterAction(self, action):
    return (self.CMD_PREFIX +
            self._FILTERACTION_FORMAT.substitute(
                name=self.term_name + self._ACTION_SUFFIX, action=action))

  def _ComposeFilter(self, srcaddr, dstaddr, proto, srcmask, dstmask,
                     srcport, dstport):
    """Convert the given parameters to a netsh filter rule string."""
    atoms = []

    if srcmask == 0:
      atoms.append(self._ADDR_ATOM.substitute(dir='src', addr='any', mask=''))
    else:
      mask_atom = self._MASK_ATOM.substitute(dir='src', mask=srcmask)
      atoms.append(self._ADDR_ATOM.substitute(
          dir='src', addr=srcaddr, mask=mask_atom))

    if dstmask == 0:
      atoms.append(self._ADDR_ATOM.substitute(dir='dst', addr='any', mask=''))
    else:
      mask_atom = self._MASK_ATOM.substitute(dir='dst', mask=dstmask)
      atoms.append(self._ADDR_ATOM.substitute(
          dir='dst', addr=dstaddr, mask=mask_atom))

    if srcport:
      atoms.append(self._PORT_ATOM.substitute(dir='src', port=srcport))
    if dstport:
      atoms.append(self._PORT_ATOM.substitute(dir='dst', port=dstport))

    if proto:
      atoms.append(self._PROTO_ATOM.substitute(protocol=proto))

    return (self.CMD_PREFIX +
            self._FILTER_FORMAT.substitute(
                name=self.term_name + self._LIST_SUFFIX,
                atoms=' '.join(atoms)))

  def ComposeRule(self, policy):
    return (self.CMD_PREFIX +
            self._RULE_FORMAT.substitute(
                name=self.term_name + '-rule', policy=policy,
                filterlist=self.term_name + self._LIST_SUFFIX,
                filteraction=self.term_name + self._ACTION_SUFFIX))


class WindowsIPSec(windows.WindowsGenerator):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'windows_ipsec'
  _TERM = Term

  _POLICY_FORMAT = Template('policy name=$name assign=yes')
  _POLICY_SUFFIX = '-policy'

  _GOOD_AFS = ['inet']

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(
        WindowsIPSec, self)._BuildTokens()

    supported_tokens -= {'icmp_type'}
    del supported_sub_tokens['icmp_type']
    return supported_tokens, supported_sub_tokens

  def _HandlePolicyHeader(self, header, target):
    policy_name = header.FilterName(self._PLATFORM) + self._POLICY_SUFFIX
    target.append(Term.CMD_PREFIX +
                  self._POLICY_FORMAT.substitute(name=policy_name) + '\n')

  def _HandleTermFooter(self, header, term, target):
    target.append(
        term.ComposeRule(header.FilterName(self._PLATFORM)) + '\n')
