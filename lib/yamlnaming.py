# Copyright 2011 Capirca Project Authors All Rights Reserved.
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

"""Parse naming definition files.

Network access control applications use definition files which contain
information about networks and services.  This naming class
will provide an easy interface into using these definitions.

Sample usage with definition files contained in ./acl/yamldefs:
    defs = Naming('acl/yamldefs/')

    services =  defs.GetService('DNS')
      returns ['53/tcp', '53/udp', ...]

    networks = defs.GetNet('INTERNAL')
      returns a list of nacaddr.IPv4 object

The definition files are contained in a single directory and
may consist of multiple files ending in .yml.  The
format of the files consists of a 'token' value, followed by a
list of values and optional comments, such as:

INTERNAL:
  - 10.0.0.0/8     [RFC-1918]
  - 172.16.0.0/12  [RFC-1918]
  - 192.168.0.0/16 [RFC-1918]

or

INTERNAL: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16  [RFC-1918]

DNS: 53/tcp, 53/udp

Note that the above is not _strictly_ YAML, as array values should be
written "[x, y]", and not just "x, y".

NOTES: This code was copied from the original Capirca Naming class
(lib.naming.Naming) and heavily modified for YAML.  Relevant changes:

- ParseServiceList and ParseNetworkList removed in favor
  of Append and AppendFromStream

"""

__author__ = 'jzohrab@gmail.com'

import re
import glob
import yaml
import nacaddr
from yaml.constructor import ConstructorError

try:
  from yaml import CLoader as Loader
except ImportError:
  from yaml import Loader


# TODO fix: extract all naming errors to common module, reuse for naming.py and yamlnaming.py.

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


class UnexpectedDefinitionType(Error):
  """An unexpected/unknown definition type was used."""

class BadYamlFormatError(Error):
  """The YAML was badly formatted, or lacked some necessary data."""

class InfiniteLookupLoopError(Error):
  """The YAML data contains an infinite loop."""

class YamlNaming(object):
  """Object to hold naming objects from NETWORK and SERVICES definition files.

  Attributes:
     services: A collection of all of the current service item tokens.
     networks: A collection of all the current network item tokens.
  """


  def __init__(self, naming_dir = None):
    """Set the default values for a new Naming object.

    Args:
      naming_dir: optional directory with .yml files.
    """

    self.services = {}
    self.networks = {}

    if naming_dir is not None:
      self.LoadYamlFromDirectory(naming_dir)


  @staticmethod
  def yaml_token_predicate(t):
    """Return True if the value t can be interpreted as a token."""
    v = t
    if type(t) is tuple:
      v = t[0]
    return re.search(r'^[A-Z_][A-Z0-9_-]+$', v)

  @staticmethod
  def RecursiveLookup(dictionary, key, recursive_predicate, raise_if_missing=ValueError):
    """Lookup and recurse, given entries in values matching the predicate.

    Given a dictionary and a key, returns values and metadata, including further
    lookups for value entries matching the predicate.

    Example: given dict { 'A': [1, 'B'], 'B': [2] },
    looking up 'A' should yield [1, 2] if the recursive_predicate
    returns True for all-caps entries, and should yield [1, 'B']
    if the recursive_predicate returns False.

    Args:
      dictionary: the dict
      key: the key
      recursive_predicate: test on token to see if should recurse
      raise_if_missing: Error to throw if missing token
    """

    def _do_lookup(dictionary, key, should_recurse_predicate, result,
                   initial_key, visited_keys, raise_if_missing):
      """Iterative recurse.
      Args:
        dictionary: the dict
        key: the current key
        should_recurse_predicate: test on token to see if should recurse
        initial_key: the initial lookup
        visited_keys: keys that have already been recursed
      """
      if key not in dictionary:
        msg = "Missing {0} (starting from key {1})"
        raise raise_if_missing(msg.format(key, initial_key))

      visited_keys.append(key)

      vals = dictionary[key]
      if not (type(vals) is list):
        vals = [vals]

      def build_metadata_tuple(a):
        value = a
        comment = None
        if type(a) is tuple:
          value = a[0]
          comment = a[1]
        return (value, comment, key, initial_key)

      atoms = [v for v in vals if not should_recurse_predicate(v)]
      atoms_with_metadata = map(build_metadata_tuple, atoms)
      result.extend(atoms_with_metadata)

      for child_key in [v[0] for v in vals if should_recurse_predicate(v)]:
        if child_key in visited_keys:
          msg = 'infinite loop between {0} and {1}'.format(initial_key, key)
          raise InfiniteLookupLoopError(msg)

        _do_lookup(dictionary, child_key, should_recurse_predicate, result,
                   initial_key, visited_keys, raise_if_missing)
      return result
    # end _do_lookup iterative function.

    return _do_lookup(dictionary, key, recursive_predicate, [],
                      key, [], raise_if_missing)


  def GetIpParents(self, query):
    """Return network tokens that contain IP in query.

    Args:
      query: an ip string ('10.1.1.1') or nacaddr.IP object
    """

    if type(query) != nacaddr.IPv4 and type(query) != nacaddr.IPv6:
      if query[:1].isdigit():
        query = nacaddr.IP(query)

    is_address_query = (type(query) in (nacaddr.IPv4, nacaddr.IPv6))
    def query_matches_or_is_contained_by(item_tup):
      item = item_tup[0]
      if is_address_query:
        return item[:1].isdigit() and nacaddr.IP(item).Contains(query)
      else:
        return item[:1].isalpha() and item == query

    base_parents = []
    for token, nets in self.networks.iteritems():
      if len([n for n in nets if query_matches_or_is_contained_by(n)]) > 0:
        base_parents.append(token)

    parents = []
    for bp in base_parents:
      parents.extend(self._GetParents(bp, self.networks))
      parents.append(bp)
    return sorted(list(set(parents)))

  def GetServiceParents(self, query):
    """Given a query token, return list of services definitions with that token.

    Args:
      query: a service token name.
    """
    return self._GetParents(query, self.services)

  def GetNetParents(self, query):
    """Given a query token, return list of network definitions with that token.

    Args:
      query: a network token name.
    """
    return self._GetParents(query, self.networks)

  def __get_entries(self, group):
    """Group entries are stored internally as (value, comment)."""
    return map(lambda x: x[0], group)

  def _GetParents(self, query, query_group):
    """Given a naming item dict, return any tokens containing the value.

    Args:
      query: a service or token name, such as 53/tcp or DNS
      query_group: either services or networks dict
    """
    base_parents = []
    recursive_parents = []
    # collect list of tokens containing query
    for token in query_group:
      if query in self.__get_entries(query_group[token]):
        base_parents.append(token)
    if not base_parents:
      return []
    # iterate through tokens containing query, doing recursion if necessary
    for bp in base_parents:
      for token in query_group:
        if bp in self.__get_entries(query_group[token]) and bp not in recursive_parents:
          recursive_parents.append(bp)
          recursive_parents.extend(self._GetParents(bp, query_group))
      if bp not in recursive_parents:
        recursive_parents.append(bp)
    return recursive_parents

  def GetService(self, query):
    """Given a service name, return a list of associated ports and protocols.

    Args:
      query: Service name symbol or token.

    Returns:
      A list of service values such as ['80/tcp', '443/tcp', '161/udp', ...]
    """
    r = self.RecursiveLookup(
      self.services,
      query.strip(),
      self.yaml_token_predicate,
      UndefinedServiceError
    )
    return [t[0] for t in r]

  def GetServiceByProto(self, query, proto):
    """Given a service name, return list of ports in the service by protocol.

    Args:
      query: Service name to lookup.
      proto: A particular protocol to restrict results by, such as 'tcp'.

    Returns:
      A list of service values of type 'proto', such as ['80', '443', ...]
    """
    proto = proto.upper()
    candidates = [s for s in self.GetService(query.strip()) if '/' in s]
    candidates = map(lambda x: x.upper().split('/'), candidates)
    return sorted([s[0] for s in candidates if s[1] == proto])

  def GetNetAddr(self, token):
    """Dup of self.GetNet"""
    return self.GetNet(token)

  def GetNet(self, query):
    """Expand a network token into a list of nacaddr.IPv4 objects.

    Args:
      query: Network definition token

    Raises:
      BadNetmaskTypeError: Results when an unknown netmask_type is
      specified.  Acceptable values are 'cidr', 'netmask', and 'hostmask'.

    Returns:
      List of nacaddr.IPv4 objects

    Raises:
      UndefinedAddressError: for an undefined token value
    """

    def make_address(net_tuple):
        net = net_tuple[0].strip()
        addr = nacaddr.IP(net)
        # we want to make sure that we're storing the network addresses
        # ie, FOO = 192.168.1.1/24 should actually return 192.168.1.0/24
        if addr.ip != addr.network:
          addr = nacaddr.IP('%s/%d' % (addr.network, addr.prefixlen))
        addr.text = net_tuple[1]
        addr.token = net_tuple[2]
        addr.parent_token = net_tuple[3]
        return addr

    nets = self.RecursiveLookup(
      self.networks,
      query.strip(),
      self.yaml_token_predicate,
      UndefinedAddressError
    )

    return map(make_address, nets)


  @staticmethod
  def _process(vals):
      """Collapse arrays of delimited lists with comments to a single list.
      Each element in the final list is a diad of (value, comment).

      Examples:
      'hello, there [comment]' => [('hello', 'comment'), ('there', 'comment')]
      """
      ret = []
      if isinstance(vals, str):
        vals = [vals]
      for raw_data in vals:
        comment = None
        if '[' not in raw_data:
          real_vals = raw_data
        else:
          data = raw_data.split('[')
          real_vals = data[0]
          comment = data[1]
          comment = comment.replace(']', '')
        ret.extend(map(lambda x: (x.strip(), comment), real_vals.split(',')))
      return ret


  def LoadYamlFromDirectory(self, defdirectory):
    """Parse yml files for tokens and values.

    Given a directory name, grab all yml files in that directory
    and parse them for definitions.

    Args:
      defdirectory: Path to directory containing definition files.

    Raises:
      NoDefinitionsError: if no definitions are found.
    """

    file_names = glob.glob(defdirectory + '/*.yml')

    if not file_names:
      tmp = 'No definition files found in {0}'.format(defdirectory)
      raise NoDefinitionsError(tmp)

    for current_file in file_names:
      with open(current_file, 'r') as f:
        y = yaml.load(f.read())
        self.Append(y)


  def Append(self, yml_data):
    """Append the yml to the network and services.

    Args:
      yml_data: yml data to load."""
    if 'network' in yml_data:
      for net, vals in yml_data['network'].iteritems():
        self.__raise_on_duplicate_key(self.networks, net, vals)
        self.networks[net] = self._process(vals)
    if 'services' in yml_data:
      for svc, vals in yml_data['services'].iteritems():
        self.__raise_on_duplicate_key(self.services, svc, vals)
        self.services[svc] = self._process(vals)
    unknowns = [k for k in yml_data if k not in ('network', 'services')]
    if len(unknowns) > 0:
      raise BadYamlFormatError('unknown keys {0}'.format(unknowns))

  def __raise_on_duplicate_key(self, dictionary, key, value):
    """Raise BadYamlFormatError if the key is already in the dictionary."""
    if key in dictionary:
      msg = "Duplicate/overwrite of key {0} (existing value '{1}', new value '{2}'"
      msg = msg.format(key, dictionary[key], value)
      raise BadYamlFormatError(msg)

  def AppendFromStream(self, stream):
    """Check YAML data stream for duplicate keys, then call Append.

    Args:
      stream: yaml data source with possible duplicates.
    """

    def no_duplicates_constructor(loader, node, deep=False):
      """Check for duplicate keys."""
      mapping = {}
      for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        self.__raise_on_duplicate_key(mapping, key, value)
        mapping[key] = value
      return loader.construct_mapping(node, deep)

    def construct_mapping(loader, node):
      loader.flatten_mapping(node)
      return object_pairs_hook(loader.construct_pairs(node))

    class DupCheckLoader(yaml.Loader):
      """Local class to prevent pollution of global yaml.Loader."""
      pass

    DupCheckLoader.add_constructor(
      yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
      no_duplicates_constructor)

    yml = yaml.load(stream, DupCheckLoader)

    self.Append(yml)

