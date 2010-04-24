#!/usr/bin/python2.4
#
# Copyright 2010 Google Inc. All Rights Reserved.
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


"""One-line documentation for silverpeak module.

A detailed description of silverpeak.
"""

__author__ = 'jfz@google.com (Joseph Zhou) & andrewlv@google.com (Hongli Lv)'


# generic error class
class Error(Exception):
  pass


# no silverpeak policy error
class NoSilverpeakPolicyError(Exception):
  pass


class Term(object):
  """Representation of an individual Silverpeak term.

    Args:
      term: policy.Term object
  """

  def __init__(self, term):
    self.term = term

  def _FixIPv6Address(self, netblocks):
    """Remove IPv6 address from netblock list.

    Args:
      netblocks: A list of IPV4 or IPV6 object.

    Returns:
      A boolean indicate whether netblocks are all ipv6 address.
      A list of only IPV4 object.
    """
    new_list = []
    length = len(netblocks)
    if length > 0:
      number_ipv6 = 0
      for netblock in netblocks:
        if netblock.version == 4:
          new_list.append(netblock)
        elif netblock.version == 6:
          number_ipv6 += 1
      if number_ipv6 == length:
        return True, new_list
    return False, new_list

  def _FixLongList(self, long_list, chunk_size):
    """Break a list to chunks according to chunk_size.

    Args:
      long_list: Target list will be devided.
      chunk_size: Sub list length.
    Returns:
      A list of list.
    """
    split_list = []
    length = len(long_list)
    if length > chunk_size:
      list_size = chunk_size - 1
      pages, mod = divmod(length, list_size)
      if mod:
        pages += 1
      for page in range(pages):
        split_list.append(long_list[list_size * page:list_size * (page+1)])
    else:
      split_list.append(long_list)
    return split_list

  def _NormalizeNetblocks(self, netblock_list):
    """Convert sub list of netblocks to string.

    Args:
      netblock_list: A list of list of netblocks.

    Returns:
      A list of string.
    """
    netblocks = []
    for sub_list in netblock_list:
      if sub_list:
        netblocks.append(','.join(str(netblock) for netblock in sub_list))
      else:
        netblocks.append('any')
    return netblocks

  def _NormalizePortRanges(self, port_ranges):
    """Convert sub list of port ranges to string.

    Args:
      port_ranges: A list of list of port pairs.

    Returns:
      A list of string.
    """
    ports = []
    for port_range in port_ranges:
      port_list = []
      if port_range:
        for port_pair in port_range:
          if port_pair[0] == port_pair[1]:
            port_list.append(str(port_pair[0]))
          else:
            port_list.append('%s-%s' % (port_pair[0], port_pair[1]))
      else:
        port_list.append('any')
      ports.append(','.join(port_list))
    return ports

  def GenerateUnitList(self):
    """Normalize and split ip&ports.

    Returns:
      A list of tuple in format:
        [(src_ip, src_port, dst_ip, dst_port),
        (src_ip, src_port, dst_ip, dst_port)]
    """
    ret_str = []
    if 'established' in self.term.option:
      dst_ports = ['any']
    else:
      dst_ports = self._NormalizePortRanges(
          self._FixLongList(self.term.destination_port, 10)
          )
    source_all_ipv6, source_address = self._FixIPv6Address(
        self.term.source_address
        )
    if source_all_ipv6:
      return ret_str
    destination_all_ipv6, destination_address = self._FixIPv6Address(
        self.term.destination_address
        )
    if destination_all_ipv6:
      return ret_str
    src_ips = self._NormalizeNetblocks(self._FixLongList(source_address, 50))
    src_ports = self._NormalizePortRanges(
        self._FixLongList(self.term.source_port, 10)
        )
    dst_ips = self._NormalizeNetblocks(
        self._FixLongList(destination_address, 50)
        )
    for src_ip in src_ips:
      for src_port in src_ports:
        for dst_ip in dst_ips:
          for dst_port in dst_ports:
            ret_str.append((src_ip, src_port, dst_ip, dst_port))
    return ret_str


class Silverpeak(object):
  """ACL and CONF rendering class.

    This class takes a policy object and renders the output into a syntax which
    is understood by silverpeak.

  Args:
    pol: policy.Policy object
  """
  # silverpeak module acl output file extension.
  _SUFFIX = '.spk'
  # silverpeak module output configuration file extension.
  _CONF_SUFFIX = '.conf'

  # qos value map in configuration file.
  qos_value_map = {'be1': 'be',
                   'af1': 'cs1',
                   'af2': 'cs2',
                   'af3': 'cs3',
                   'af4': 'cs4',
                   'af5': 'cs5',
                   'nc1': 'cs6'
                  }

  # Ignore terms that "starts", "ends", or "contains" the following text
  # You can define multiple "starts", "ends" or "contains" terms.
  # The following are just examples - commonly used when a policy
  # is used to generate output for multiple platforms.
  exception_term_rule = {}
  # Sample usage:
  #exception_term_rule = {'klaatu': 'starts',
  #                       'barada': 'contains',
  #                       'nikto': 'ends'
  #                      }

  def __init__(self, pol):
    for header in pol.headers:
      if 'silverpeak' not in header.platforms:
        raise NoSilverpeakPolicyError(" '%s' is not a silverpeak target" %
                                      header.target)
    self.policy = pol

  def __str__(self):
    """Method same as other modules for render_policy in aclgen.py if need."""
    return self.GenerateACLString()

  def _CheckExceptionTerm(self, term, rules):
    """Check if term matches exception rules.

    Args:
      term: a string of term name to check.
      rules: a dict of exception term name and match behavior.

    Returns:
      True if term match one of the rules.
    """
    flag = False
    for keyword in rules:
      if rules[keyword] == 'starts':
        flag = flag or term.startswith(keyword)
      if rules[keyword] == 'ends':
        flag = flag or term.endswith(keyword)
      if rules[keyword] == 'contains':
        flag = flag or (keyword in term)
    return flag

  def GenerateACLString(self):
    """Generate ACL file content in string format."""
    target_string = ''
    target = []  # list of strings used to formulate final string.
    app_id = 0  # variable in ACL sentenses.
    unit_list = []
    for header, terms in self.policy.filters:
      for term in terms:
        # for term belongs to term exception, skip to next term.
        if self._CheckExceptionTerm(term.name, self.exception_term_rule):
          continue
        unit_list = Term(term).GenerateUnitList()
        for unit in unit_list:
          app_id += 100
          target.append('application')
          target.append(str(app_id))
          target.append(term.name)
          target.append('protocol')
          if term.protocol:
            term.protocol.sort()
            target.append('/'.join(term.protocol))
          else:
            target.append('ip')
          target.append('src-ip %s src-port %s' % (unit[0], unit[1]))
          target.append('dst-ip %s dst-port %s' % (unit[2], unit[3]))
          target.append('dscp any\n\n')
          target_string += ' '.join(target)
          target = []
    # formulate the return string
    return target_string

  def GenerateConfString(self):
    """Generate configuration file."""
    target_string = ''
    target = []
    unit_list = []
    for header, terms in self.policy.filters:
      for term in terms:
        if self._CheckExceptionTerm(term.name, self.exception_term_rule):
          continue
        unit_list = Term(term).GenerateUnitList()
        if unit_list:
          if term.qos in self.qos_value_map:
            qos_value = self.qos_value_map[term.qos]
            target.append('match protocol ip src-ip any src-port any')
            target.append('dst-ip any dst-port any application')
            target.append(term.name)
            target.append('dscp any set traffic-class 1')
            target.append('lan-qos-dscp %s wan-qos-dscp %s\n\n' %
                          (qos_value, qos_value))
            target_string += ' '.join(target)
            target = []
    return target_string


def main():
  pass


if __name__ == '__main__':
  pass
