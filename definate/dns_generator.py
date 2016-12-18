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

"""Generator for DNS based network definitions."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import logging
import socket

from third_party import ipaddr
import generator


class DnsGeneratorError(Exception):
  """Exception to use when DnsGenerator fails."""


class DnsGenerator(generator.Generator):
  """Generator implementation for network definitions based on DNS."""

  SUPPORTED_TYPES = ['A', 'AAAA']

  def GenerateDefinition(self, config, unused_global_config):
    """Generates a list of all nodes in a network definition.

    This method basically processes all the configuration which is
    hierarchically below "networks" in the "definitions" section in the
    configuration file to generate a list of all nodes in that definition.

    Args:
      config: YAML configuration structure (dictionaries, lists and strings)
        representing the "networks" section in "definitions" of the
        configuration file.
      unused_global_config: YAML configuration structure (dictionaries, lists
        and strings) representing the "global" section of the configuration
        file.

    Returns:
      Tuples of IPNetwork objects and string comments representing all the nodes
      in one definition.

    Raises:
      DefinateConfigError: The configuration is not well formed.
      DnsGeneratorError: There is a problem generating the output.
    """
    nodes = []
    yaml_structure = {
        'names': ['str'],
        'types': ['str'],
        }
    for network in config:
      self._yaml_validator.CheckConfiguration(network, yaml_structure)
      for typ in network['types']:
        if typ not in self.SUPPORTED_TYPES:
          raise DnsGeneratorError('Unsupported DNS type found: %s' % typ)
      for name in network['names']:
        try:
          addr_list = socket.getaddrinfo(name, None)
        except socket.gaierror:
          raise DnsGeneratorError('Hostname not found: %s' % name)
        for family, _, _, _, sockaddr in addr_list:
          ip_addr = None
          if family == socket.AF_INET and 'A' in network['types']:
            # sockaddr = (address, port)
            ip_addr = ipaddr.IPv4Network(sockaddr[0])
          elif family == socket.AF_INET6 and 'AAAA' in network['types']:
            # sockaddr = (address, port, flow info, scope id)
            ip_addr = ipaddr.IPv6Network(sockaddr[0])
          else:
            logging.debug('Skipping unknown AF \'%d\' for: %s', family, name)
          if ip_addr:
            nodes.append((ip_addr, name))
    return nodes
