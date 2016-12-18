#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module that holds all definition-level filter classes of Definate."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import logging


class Container(object):
  """Container class to hold all information to be passed between filters."""

  def __init__(self, header=None, name='', entries_and_comments=None,
               string_representation=''):
    """Initializer.

    Args:
      header: Optional list of strings to be added as headers.
      name: Optional string representing the name of the definition.
      entries_and_comments: Optional list of tuples (entries, comments) which
        hold all entries for one definition as well as comments.
      string_representation: Optional string holding the string representation
        of the definition (typically used as output e.g. in a file in the end).
    """
    self.header = header if header else []
    self.name = name
    self.entries_and_comments = (
        entries_and_comments if entries_and_comments else [])
    self.string_representation = string_representation


class DefinitionFilter(object):
  """Abstract class defining the interface for the filter chain objects."""

  def Filter(self, container, args):
    """Interface to filter or modify data passed into it.

    Args:
      container: Container object which holds all information for one
        definition. See Container class for details.
      args: Dictionary of arguments depending on the actual filter in use.

    Raises:
      NotImplementedError: In any case since this is not implemented an needs
        to be defined by subclasses.
    """
    raise NotImplementedError(
        'This is an interface only. Implemented by subclasses.')


class SortFilter(DefinitionFilter):
  """DefinitionFilter implementation which sorts all entries for nice output."""

  def Filter(self, container, unused_args):
    """Filter method that sorts all entries in a definition for nice output.

    The filter sorts all entries in ascending order:
    - IPv4 networks
    - IPv6 networks

    Args:
      container: Container object which holds all information for one
        definition. See Container class for details.
      unused_args: No extra arguments required by this filter implementation.

    Returns:
      Container object that has been passed in.
    """
    ipv4_nodes = []
    ipv6_nodes = []

    for node, comment in container.entries_and_comments:
      if node.version == 4:
        ipv4_nodes.append((node, comment))
      elif node.version == 6:
        ipv6_nodes.append((node, comment))
      else:
        logging.warn('Unsupported address version detected: %s', node.version)

    ipv4_nodes = self._RemoveDuplicateNetworks(ipv4_nodes)
    ipv6_nodes = self._RemoveDuplicateNetworks(ipv6_nodes)

    ipv4_nodes.sort()
    ipv6_nodes.sort()

    container.entries_and_comments = ipv4_nodes + ipv6_nodes
    return container

  def _RemoveDuplicateNetworks(self, network_list):
    """Method to remove duplicate networks from the network list.

    Args:
      network_list: List of node/comment tuples where node is an IPNetwork
        object and comment is a string.

    Returns:
      The same list of networks and comments minus duplicate entries.
    """
    result_list = []
    result_dict = {}
    for node, comment in network_list:
      result_dict[str(node)] = (node, comment)
    for node in result_dict:
      result_list.append(result_dict[node])
    return result_list


class AlignFilter(DefinitionFilter):
  """DefinitionFilter implementation which generates nicely aligned output."""

  def Filter(self, container, unused_args):
    """Filter method that aligns the entries in the output nicely.

    This code formats the entries_and_comments by figuring out the
    left-justification from the definition name ('name'), and padding the
    left justification of the comments to 3 spaces after the longest entry
    length.

    In order to do this succinctly, without adding strings together, we use a
    format string that we replace twice.  Once for the (left|right)
    justification bounds, and again with the final values.

    Args:
      container: Container object which holds all information for one
        definition. See Container class for details.
      unused_args: No extra arguments required by this filter implementation.

    Returns:
      Container object that has been passed in.
    """
    first_format_string = '%%s = %%%is# %%s'
    format_string = '%%%is%%%is# %%s'

    max_len = max(len(str(e)) for e, _ in container.entries_and_comments)
    value_justification = -1 * (max_len + 3)
    column_justification = len(container.name) + 3  # 3 for ' = '

    first_format_string %= value_justification
    format_string %= (column_justification, value_justification)

    entry, comment = container.entries_and_comments[0]
    first_string = first_format_string % (container.name, entry, comment)
    output = [first_string]

    for entry, comment in container.entries_and_comments[1:]:
      output.append(format_string % ('', entry, comment))

    container.string_representation = '\n'.join(output)
    return container
