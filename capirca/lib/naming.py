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

"""Parse naming definition files.

Network access control applications use definition files which contain
information about networks and services.  This naming class
will provide an easy interface into using these definitions.

Sample usage with definition files contained in ./acl/defs:
    defs = Naming('acl/defs/')

    services =  defs.GetService('DNS')
      returns ['53/tcp', '53/udp', ...]

    networks = defs.GetNet('INTERNAL')
      returns a list of nacaddr.IPv4 object

The definition files are contained in a single directory and
may consist of multiple files ending in .net or .svc extensions,
indicating network or service definitions respectively.  The
format of the files consists of a 'token' value, followed by a
list of values and optional comments, such as:

INTERNAL = 10.0.0.0/8     # RFC-1918
           172.16.0.0/12  # RFC-1918
           192.168.0.0/16 # RFC-1918
or

DNS = 53/tcp
      53/udp

"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import glob
import os
import re

from capirca.lib import nacaddr
from capirca.lib import port as portlib




class Error(Exception):
  """Create our own base error class to be inherited by other error classes."""


class NamespaceCollisionError(Error):
  """Used to report on duplicate symbol names found while parsing."""


class BadNetmaskTypeError(Error):
  """Used to report on duplicate symbol names found while parsing."""


class NoDefinitionsError(Error):
  """Raised if no definitions are found."""


class ParseError(Error):
  """Raised if an error occurs during parsing."""


class UndefinedAddressError(Error):
  """Raised if an address is referenced but not defined."""


class UndefinedServiceError(Error):
  """Raised if a service is referenced but not defined."""


class UndefinedPortError(Error):
  """Raised if a port/protocol pair has not been defined."""


class UnexpectedDefinitionType(Error):
  """An unexpected/unknown definition type was used."""


class NamingSyntaxError(Error):
  """A general syntax error for the definition."""


class _ItemUnit(object):
  """This class is a container for an index key and a list of associated values.

  An ItemUnit will contain the name of either a service or network group,
  and a list of the associated values separated by spaces.

  Attributes:
    name: A string representing a unique token value.
    items: a list of strings containing values for the token.
  """

  def __init__(self, symbol):
    self.name = symbol
    self.items = []


class Naming(object):
  """Object to hold naming objects from NETWORK and SERVICES definition files.

  Attributes:
     current_symbol: The current token being handled while parsing data.
     services: A collection of all of the current service item tokens.
     networks: A collection of all the current network item tokens.
  """

  def __init__(self, naming_dir=None, naming_file=None, naming_type=None):
    """Set the default values for a new Naming object."""
    self.current_symbol = None
    self.services = {}
    self.networks = {}
    self.unseen_services = {}
    self.unseen_networks = {}
    self.port_re = re.compile(r'(^\d+-\d+|^\d+)\/\w+$|^[\w\d-]+$',
                              re.IGNORECASE|re.DOTALL)
    if naming_file and naming_type:
      filename = os.path.sep.join([naming_dir, naming_file])
      file_handle = open(filename, 'r')
      self._ParseFile(file_handle, naming_type)
    elif naming_dir:
      self._Parse(naming_dir, 'services')
      self._CheckUnseen('services')

      self._Parse(naming_dir, 'networks')
      self._CheckUnseen('networks')

  def _CheckUnseen(self, def_type):
    if def_type == 'services':
      if self.unseen_services:
        raise UndefinedServiceError('%s %s' % (
            'The following tokens were nested as a values, but not defined',
            self.unseen_services))
    if def_type == 'networks':
      if self.unseen_networks:
        raise UndefinedAddressError('%s %s' % (
            'The following tokens were nested as a values, but not defined',
            self.unseen_networks))

  def GetIpParents(self, query):
    """Return network tokens that contain IP in query.

    Args:
      query: an ip string ('10.1.1.1') or nacaddr.IP object

    Returns:
      A sorted list of unique parent tokens.
    """
    base_parents = []
    recursive_parents = []
    # convert string to nacaddr, if arg is ipaddr then convert str() to nacaddr
    if (not isinstance(query, nacaddr.IPv4) and
        not isinstance(query, nacaddr.IPv6)):
      if query[:1].isdigit():
        query = nacaddr.IP(query)
    # Get parent token for an IP
    if isinstance(query, nacaddr.IPv4) or isinstance(query, nacaddr.IPv6):
      for token in self.networks:
        for item in self.networks[token].items:
          item = item.split('#')[0].strip()
          if not item[:1].isdigit():
            continue
          try:
            if nacaddr.IP(item).Contains(query):
              base_parents.append(token)
          except ValueError:
            # item was not an IP
            pass
    # Get parent token for another token
    else:
      for token in self.networks:
        for item in self.networks[token].items:
          item = item.split('#')[0].strip()
          if item[:1].isalpha() and item == query:
            base_parents.append(token)
    # look for nested tokens
    for bp in base_parents:
      done = False
      for token in self.networks:
        if bp in [item.split('#')[0].strip() for item in
                  self.networks[token].items]:
          # ignore IPs, only look at token values
          if bp[:1].isalpha():
            if bp not in recursive_parents:
              recursive_parents.append(bp)
              recursive_parents.extend(self.GetIpParents(bp))
            done = True
      # if no nested tokens, just append value
      if not done:
        if bp[:1].isalpha() and bp not in recursive_parents:
          recursive_parents.append(bp)
    return sorted(list(set(recursive_parents)))

  def GetServiceParents(self, query):
    """Given a query token, return list of services definitions with that token.

    Args:
      query: a service token name.
    Returns:
      List of service definitions containing the token.
    """
    return self._GetParents(query, self.services)

  def GetNetParents(self, query):
    """Given a query token, return list of network definitions with that token.

    Args:
      query: a network token name.
    Returns:
      A list of network definitions containing the token.
    """
    return self._GetParents(query, self.networks)

  def _GetParents(self, query, query_group):
    """Given a naming item dict, return any tokens containing the value.

    Args:
      query: a service or token name, such as 53/tcp or DNS
      query_group: either services or networks dict

    Returns:
      Returns a list of definitions containing the token in desired group.
    """
    base_parents = []
    recursive_parents = []
    # collect list of tokens containing query
    for token in query_group:
      if query in [item.split('#')[0].strip() for item in
                   query_group[token].items]:
        base_parents.append(token)
    if not base_parents:
      return []
    # iterate through tokens containing query, doing recursion if necessary
    for bp in base_parents:
      for token in query_group:
        if bp in query_group[token].items and bp not in recursive_parents:
          recursive_parents.append(bp)
          recursive_parents.extend(self._GetParents(bp, query_group))
      if bp not in recursive_parents:
        recursive_parents.append(bp)
    return recursive_parents

  def GetServiceNames(self):
    """Returns the list of all known service names."""
    return list(self.services.keys())

  def GetService(self, query):
    """Given a service name, return a list of associated ports and protocols.

    Args:
      query: Service name symbol or token.

    Returns:
      A list of service values such as ['80/tcp', '443/tcp', '161/udp', ...]

    Raises:
      UndefinedServiceError: If the service name isn't defined.
    """
    expandset = set()
    already_done = set()
    data = []
    service_name = ''
    data = query.split('#')     # Get the token keyword and remove any comment
    service_name = data[0].split()[0]  # strip and cast from list to string
    if service_name not in self.services:
      raise UndefinedServiceError('\nNo such service: %s' % query)

    already_done.add(service_name)

    for next_item in self.services[service_name].items:
      # Remove any trailing comment.
      service = next_item.split('#')[0].strip()
      # Recognized token, not a value.
      if '/' not in service:
        # Make sure we are not descending into recursion hell.
        if service not in already_done:
          already_done.add(service)
          try:
            expandset.update(self.GetService(service))
          except UndefinedServiceError as e:
            # One of the services in query is undefined, refine the error msg.
            raise UndefinedServiceError('%s (in %s)' % (e, query))
      else:
        expandset.add(service)
    return sorted(expandset)

  def GetPortParents(self, query, proto):
    """Returns a list of all service tokens containing the port/protocol pair.

    Args:
        query: port number ('22') as str
        proto: protocol name ('tcp') as str

    Returns:
        A list of service tokens: ['SSH', 'HTTPS']

    Raises:
      UndefinedPortError: If the port/protocol pair isn't used in any
      service tokens.
    """
    # turn the given port and protocol into a PortProtocolPair object
    given_ppp = portlib.PPP(query + '/' + proto)
    base_parents = []
    matches = set()
    # check each service token to see if it's a PPP or a nested group.
    # if it's a PPP, see if there's a match with given_ppp
    # otherwise, add nested group to a list to recurisvely check later.
    # if there's no match, do nothing.
    for service_token in self.services:
      for port_child in self.services[service_token].items:
        ppp = portlib.PPP(port_child)
        # check for exact match
        if ppp.is_single_port and ppp == given_ppp:
          matches.add(service_token)
        # check if it's within ppp's port range
        elif ppp.is_range and given_ppp in ppp:
          matches.add(service_token)
        # if it's a nested token, add to a list to recurisvely
        # check later.
        elif ppp.nested:
          if service_token not in base_parents:
            base_parents.append(service_token)
    # break down the nested service tokens into PPP objects and check
    # against given_ppp
    for bp in base_parents:
      for port_child in self.GetService(bp):
        ppp = portlib.PPP(port_child)
        # check for exact match
        if ppp.is_single_port and ppp == given_ppp:
          matches.add(bp)
        # check if it's within ppp's port range
        elif ppp.is_range and given_ppp in ppp:
          matches.add(bp)
    # error if the port/protocol pair is not found.
    if not matches:
      raise UndefinedPortError(
          '%s/%s is not found in any service tokens' % (query, proto))
    return sorted(matches)

  def GetServiceByProto(self, query, proto):
    """Given a service name, return list of ports in the service by protocol.

    Args:
      query: Service name to lookup.
      proto: A particular protocol to restrict results by, such as 'tcp'.

    Returns:
      A list of service values of type 'proto', such as ['80', '443', ...]

    Raises:
      UndefinedServiceError: If the service name isn't defined.
    """
    services_set = set()
    proto = proto.upper()
    data = []
    servicename = ''
    data = query.split('#')     # Get the token keyword and remove any comment
    servicename = data[0].split()[0]  # strip and cast from list to string
    if servicename not in self.services:
      raise UndefinedServiceError('%s %s' % ('\nNo such service,', servicename))

    for service in self.GetService(servicename):
      if service and '/' in service:
        parts = service.split('/')
        if parts[1].upper() == proto:
          services_set.add(parts[0])
    return sorted(services_set)

  def GetNetAddr(self, token):
    """Given a network token, return a list of netaddr.IPv4 objects.

    Args:
      token: A name of a network definition, such as 'INTERNAL'

    Returns:
      A list of netaddr.IPv4 objects.

    Raises:
      UndefinedAddressError: if the network name isn't defined.
    """
    return self.GetNet(token)

  def GetNet(self, query):
    """Expand a network token into a list of nacaddr.IPv4 objects.

    Args:
      query: Network definition token which may include comment text

    Raises:
      BadNetmaskTypeError: Results when an unknown netmask_type is
      specified.  Acceptable values are 'cidr', 'netmask', and 'hostmask'.

    Returns:
      List of nacaddr.IPv4 objects

    Raises:
      UndefinedAddressError: for an undefined token value
    """
    returnlist = []
    data = []
    token = ''
    data = query.split('#')     # Get the token keyword and remove any comment
    token = data[0].split()[0]  # Remove whitespace and cast from list to string
    if token not in self.networks:
      raise UndefinedAddressError('%s %s' % ('\nUNDEFINED:', str(token)))

    for i in self.networks[token].items:
      comment = ''
      if i.find('#') > -1:
        (net, comment) = i.split('#', 1)
      else:
        net = i
      try:
        net = net.strip()
        addr = nacaddr.IP(net)
        # we want to make sure that we're storing the network addresses
        # ie, FOO = 192.168.1.1/24 should actually return 192.168.1.0/24
        if addr.ip != addr.network:
          addr = nacaddr.IP('%s/%d' % (addr.network, addr.prefixlen))

        addr.text = comment.lstrip()
        addr.token = token
        returnlist.append(addr)
      except ValueError:
        # if net was something like 'FOO', or the name of another token which
        # needs to be dereferenced, nacaddr.IP() will return a ValueError
        returnlist.extend(self.GetNet(net))
    for i in returnlist:
      i.parent_token = token
    return returnlist

  def _Parse(self, defdirectory, def_type):
    """Parse files of a particular type for tokens and values.

    Given a directory name and the type (services|networks) to
    process, grab all the appropriate files in that directory
    and parse them for definitions.

    Args:
      defdirectory: Path to directory containing definition files.
      def_type: Type of definitions to parse

    Raises:
      NoDefinitionsError: if no definitions are found.
    """
    file_names = []
    get_files = {'services': lambda: glob.glob(defdirectory + '/*.svc'),
                 'networks': lambda: glob.glob(defdirectory + '/*.net')}

    if def_type in get_files:
      file_names = get_files[def_type]()
    else:
      raise NoDefinitionsError('Definitions type %s is unknown.' % def_type)
    if not file_names:
      raise NoDefinitionsError('No definition files for %s in %s found.' %
                               (def_type, defdirectory))

    for current_file in file_names:
      try:
        file_handle = open(current_file, 'r')
        self._ParseFile(file_handle, def_type)
      except IOError as error_info:
        raise NoDefinitionsError('%s', error_info)

  def _ParseFile(self, file_handle, def_type):
    for line in file_handle:
      self._ParseLine(line, def_type)

  def ParseServiceList(self, data):
    """Take an array of service data and import into class.

    This method allows us to pass an array of data that contains service
    definitions that are appended to any definitions read from files.

    Args:
      data: array of text lines containing service definitions.
    """
    for line in data:
      self._ParseLine(line, 'services')

  def ParseNetworkList(self, data):
    """Take an array of network data and import into class.

    This method allows us to pass an array of data that contains network
    definitions that are appended to any definitions read from files.

    Args:
      data: array of text lines containing net definitions.

    """
    for line in data:
      self._ParseLine(line, 'networks')

  def _ParseLine(self, line, definition_type):
    """Parse a single line of a service definition file.

    This routine is used to parse a single line of a service
    definition file, building a list of 'self.services' objects
    as each line of the file is iterated through.

    Args:
      line: A single line from a service definition files.
      definition_type: Either 'networks' or 'services'

    Raises:
      UnexpectedDefinitionType: called with unexpected type of definitions.
      NamespaceCollisionError: when overlapping tokens are found.
      ParseError: If errors occur
      NamingSyntaxError: Syntax error parsing config.
    """
    if definition_type not in ['services', 'networks']:
      raise UnexpectedDefinitionType('%s %s' % (
          'Received an unexpected definition type:', definition_type))
    line = line.strip()
    if not line or line.startswith('#'):  # Skip comments and blanks.
      return
    comment = ''
    if line.find('#') > -1:  # if there is a comment, save it
      (line, comment) = line.split('#', 1)
    line_parts = line.split('=')   # Split on var = val lines.
    # the value field still has the comment at this point
    # If there was '=', then do var and value
    if len(line_parts) > 1:
      self.current_symbol = line_parts[0].strip()  # varname left of '='
      if definition_type == 'services':
        for port in line_parts[1].strip().split():
          if not self.port_re.match(port):
            raise NamingSyntaxError('%s: %s' % (
                'The following line has a syntax error', line))
        if self.current_symbol in self.services:
          raise NamespaceCollisionError('%s %s' % (
              '\nMultiple definitions found for service: ',
              self.current_symbol))
      elif definition_type == 'networks':
        if self.current_symbol in self.networks:
          raise NamespaceCollisionError('%s %s' % (
              '\nMultiple definitions found for service: ',
              self.current_symbol))

      self.unit = _ItemUnit(self.current_symbol)
      if definition_type == 'services':
        self.services[self.current_symbol] = self.unit
        # unseen_services is a list of service TOKENS found in the values
        # of newly defined services, but not previously defined themselves.
        # When we define a new service, we should remove it (if it exists)
        # from the list of unseen_services.
        if self.current_symbol in self.unseen_services:
          self.unseen_services.pop(self.current_symbol)
      elif definition_type == 'networks':
        self.networks[self.current_symbol] = self.unit
        if self.current_symbol in self.unseen_networks:
          self.unseen_networks.pop(self.current_symbol)
      else:
        raise ParseError('Unknown definitions type.')
      values = line_parts[1]
    # No '=', so this is a value only line
    else:
      values = line_parts[0]  # values for previous var are continued this line
    for value_piece in values.split():
      if not value_piece:
        continue
      if not self.current_symbol:
        break
      if comment:
        self.unit.items.append(value_piece + ' # ' + comment)
      else:
        self.unit.items.append(value_piece)
        # token?
        if value_piece[0].isalpha() and ':' not in value_piece:
          if definition_type == 'services':
            # already in top definitions list?
            if value_piece not in self.services:
              # already have it as an unused value?
              if value_piece not in self.unseen_services:
                self.unseen_services[value_piece] = True
          if definition_type == 'networks':
            if value_piece not in self.networks:
              if value_piece not in self.unseen_networks:
                self.unseen_networks[value_piece] = True
