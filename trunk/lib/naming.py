#!/usr/bin/python
#
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

__author__ = 'watson@google.com (Tony Watson)'

import glob

from capirca import nacaddr


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

  def __init__(self, naming_dir=None):
    """Set the default values for a new Naming object."""
    self.current_symbol = None
    self.services = {}
    self.networks = {}
    self.networks6 = {}
    if naming_dir:
      self._Parse(naming_dir, 'services')
      self._Parse(naming_dir, 'networks')

  def GetIpParents(self, query):
    """Return network tokens that contain IP in query.

    Args:
      query: an ip string ('10.1.1.1') or nacaddr.IP object

    Returns:
      rval2: a list of tokens containing this IP
    """
    rval = []
    rval2 = []
    # convert string to nacaddr, if arg is ipaddr then convert str() to nacaddr
    if type(query) != nacaddr.IPv4 and type(query) != nacaddr.IPv6:
      if query[:1].isdigit():
        query = nacaddr.IP(query)
    # Get parent token for an IP
    if type(query) == nacaddr.IPv4 or type(query) == nacaddr.IPv6:
      for token in self.networks:
        for item in self.networks[token].items:
          item = item.split('#')[0].strip()
          if item[:1].isdigit():
            if nacaddr.IP(item).Contains(query):
              rval.append(token)
    # Get parent token for another token
    else:
      for token in self.networks:
        for item in self.networks[token].items:
          item = item.split('#')[0].strip()
          if item[:1].isalpha():
            if item == query:
              rval.append(token)
    # look for nested tokens
    for next in rval:
      done = False
      for token in self.networks:
        if next in self.networks[token].items:
          # ignore IPs, only look at token values
          if next[:1].isalpha():
            if next not in rval2:
              rval2.append(next)
              rval2.extend(self.GetIpParents(next))
            done = True
      # if no nested tokens, just append value
      if not done:
        if next[:1].isalpha():
          if next not in rval2:
            rval2.append(next)
    return sorted(list(set(rval2)))

  def GetServiceParents(self, query):
    """Given a service, return any tokens containing the value.

    Args:
      query: a service or token name, such as 53/tcp or DNS

    Returns:
      rval2: a list of tokens that contain query or parents of query
    """
    rval = []
    rval2 = []
    for token in self.services:
      for item in self.services[token].items:
        if item == query:
          rval.append(token)
    for next in rval:
      done = False
      for token in self.services:
        if next in self.services[token].items:
          if next not in rval2:
            rval2.append(next)
            rval2.extend(self.GetServiceParents(next))
          done = True
      if not done:
        if next not in rval2:
          rval2.append(next)
    return rval2

  def GetService(self, query):
    """Given a service name, return a list of associated ports and protocols.

    Args:
      query: Service name symbol or token.

    Returns:
      A list of service values such as ['80/tcp', '443/tcp', '161/udp', ...]
    """
    expandset = set()
    already_done = set()
    data = []
    service_name = ''
    data = query.split('#')     # Get the token keyword and remove any comment
    service_name = data[0].split()[0]  # strip and cast from list to string
    if service_name not in self.services:
      return []

    already_done.add(service_name)

    for next in self.services[service_name].items:
      comment = ''
      if next.find('#') > -1:
        (service, comment) = [x.strip() for x in next.split('#')]
      else:
        service = next.strip()
      # Recognized token, not a value.
      if service in self.services:
        # Make sure we are not descending into recursion hell.
        if service not in already_done:
          already_done.add(service)
          for token_within_a_service in self.GetService(service):
            expandset.add(token_within_a_service)
      else:
        expandset.add(service)
    return sorted(expandset)

  def GetServiceByProto(self, query, proto):
    """Given a service name, return list of ports in the service by protocol.

    Args:
      query: Service name to lookup.
      proto: A particular protocol to restrict results by, such as 'tcp'.

    Returns:
      A list of service values of type 'proto', such as ['80', '443', ...]
    """
    services_set = set()
    proto = proto.upper()
    data = []
    servicename = ''
    data = query.split('#')     # Get the token keyword and remove any comment
    servicename = data[0].split()[0]  # strip and cast from list to string
    if servicename not in self.services:
      return []

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
      raise UndefinedAddressError('UNDEFINED: %s' % str(token))

    for next in self.networks[token].items:
      comment = ''
      if next.find('#') > -1:
        (net, comment) = next.split('#')
      else:
        net = next
      try:
        addr = nacaddr.IP(net)
        # we want to make sure that we're storing the network addresses
        # ie, FOO = 192.168.1.1/24 should actually return 192.168.1.0/24
        if addr.ip != addr.network:
          addr = nacaddr.IP(addr.network_ext + '/' + str(addr.prefixlen))

        addr.text = comment.lstrip()
        addr.token = token
        returnlist.append(addr)
      except ValueError:
        # if net was something like 'FOO', or the name of another token which
        # needs to be dereferenced, nacaddr.IP() will return a ValueError
        returnlist.extend(self.GetNet(net))
    for next in returnlist:
      next.parent_token = token
    return returnlist

  def _Parse(self, defdirectory, dotype):
    """Parse files of a particular type for tokens and values.

    Given a directory name and the type (services|networks) to
    process, grab all the appropriate files in that directory
    and parse them for definitions.

    Args:
      defdirectory: Path to directory containing definition files.
      dotype: Type of definitions to parse

    Raises:
      NoDefinitionsError: if no definitions are found.
    """
    file_names = []
    get_files = {'services': lambda: glob.glob(defdirectory + '/*.svc'),
                 'networks': lambda: glob.glob(defdirectory + '/*.net')}

    if dotype in get_files:
      file_names = get_files[dotype]()
    else:
      raise NoDefinitionsError('Unknown definitions type.')
    if not file_names:
      raise NoDefinitionsError('No definition files found.')

    for current_file in file_names:
      try:
        file_handle = open(current_file, 'r')
        for line in file_handle:
          self._ParseLine(line, dotype)
        file_handle.close()
      except IOError, error_info:
        raise NoDefinitionsError('%s', error_info)

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
      NamespaceCollisionError: when overlapping tokens are found.
      ParseError: If errors occur
    """
    if definition_type not in ['services', 'networks']:
      return
    line = line.strip()
    if not line or line.startswith('#'):  # Skip comments and blanks.
      return
    comment = ''
    if line.find('#') > -1:  # if there is a comment, save it
      (line, comment) = line.split('#')
    line_parts = line.split('=')   # Split on var = val lines.
    # the value field still has the comment at this point
    # If there was '=', then do var and value
    if len(line_parts) > 1:
      self.current_symbol = line_parts[0].strip()  # varname left of '='
      if definition_type == 'services':
        if self.current_symbol in self.services:
          raise NamespaceCollisionError(self.current_symbol)
      elif definition_type == 'networks':
        if self.current_symbol in self.networks:
          raise NamespaceCollisionError(self.current_symbol)

      self.unit = _ItemUnit(self.current_symbol)
      if definition_type == 'services':
        self.services[self.current_symbol] = self.unit
      elif definition_type == 'networks':
        self.networks[self.current_symbol] = self.unit
      else:
        raise ParseError('Unknown definitions type.')
      values = line_parts[1]
    # No '=', so this is a value only line
    else:
      values = line_parts[0]  # values for previous var are continued this line
    for value_piece in values.split():
      if value_piece:
        if self.current_symbol:
          if comment:
            self.unit.items.append(value_piece + ' # ' + comment)
          else:
            self.unit.items.append(value_piece)
