# Copyright 2015 Google Inc. All Rights Reserved.
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

"""A simple, line-oriented parser for Caprica policies.

This parser differs from the default parser in that it preserves the original
structure and defers resolving referents to the user. This is useful for
analyzing policy structures and their use of naming data. It happens to discard
inline comments but preservers line-level comments. Fields expected to have
"naming" values are stored as a set without order or line breaks retained.
"""

from absl import logging
import six


class Field:
  """A name-value assignment within a block."""

  def __init__(self, value):
    self.value = value

  def __str__(self):
    t = type(self)
    f = 'UNKNOWN'
    for k, v in field_map.items():
      if t == v:
        f = k
        break
    indent = len(f) + 5
    return '%s::%s' % (f, self.ValueStr().replace('\n', '\n' + ' ' * indent))

  def __eq__(self, o):
    if not isinstance(o, self.__class__):
      return False
    return self.value == o.value

  def __ne__(self, o):
    return not self == o

  def Append(self, value):
    self.value += value

  def ValueStr(self):
    return self.value


class IntegerField(Field):

  def __init__(self, value):
    super().__init__(value)
    try:
      _ = int(value)
    except ValueError:
      raise ValueError('Invalid integer field: "%s"' % str(self))


class NamingField(Field):
  """A naming field is one that refers to names in used in naming.py."""

  def __init__(self, value):
    super().__init__(value)
    self.value = self.ParseString(value)

  def ParseString(self, value):
    """Split and validate a string value into individual names."""
    parts = set(value.split())
    for p in parts:
      self.ValidatePart(p)
    return parts

  def ValidatePart(self, part):
    """Validate that a string smells like a naming.py name."""
    for c in part:
      if c not in '-_.' and not c.isdigit() and not c.isupper():
        raise ValueError('Invalid name reference: "%s"' % part)

  def Append(self, value):
    """Split, validate, and add name contained within a string."""
    parts = self.ParseString(value)
    self.value.update(parts)

  def ValueStr(self):
    """Return the value as a series of lines no longer than 60 chars each."""
    values = sorted(self.value)
    line_wrap = 60
    length = 0
    line_buf = []
    value_buf = []
    for v in values:
      if length + len(v) > line_wrap:
        value_buf.append(' '.join(line_buf))
        length = 0
        line_buf = []
      else:
        if line_buf:
          length += 1
        line_buf.append(v)
        length += len(v)
    if line_buf:
      value_buf.append(' '.join(line_buf))
    return ' ' + '\n'.join(value_buf)


class Action(Field):
  """An action field."""


class Address(NamingField):
  """An address field."""


class Port(NamingField):
  """A port field."""


class Comment(Field):
  """A comment field."""

  def ValueStr(self):
    # Comments should align with the string contents, after the leading
    # quotation mark.
    return self.value.replace('\n', '\n ')


class Counter(Field):
  """A counter field."""


class Encapsulate(Field):
  """An encapsulate field."""


class Decapsulate(Field):
  """An decapsulate field."""


class DestinationAddress(Address):
  """A destination-address field."""


class DestinationExclude(Address):
  """A destination-exclude field."""


class DestinationInterface(Field):
  """A destination-interface field."""


class DestinationPort(Port):
  """A destination-port field."""


class DestinationPrefix(Field):
  """A destination-prefix field."""


class DestinationPrefixExcept(Field):
  """A destination-prefix-except field."""


class DestinationTag(Field):
  """A destination tag field."""

class DestinationZone(Field):
  """A destination-zone field."""

class DscpMatch(Field):
  """A dscp-match field."""


class DscpSet(Field):
  """A dscp-set field."""


class EtherType(Field):
  """An ether-type field."""


class Expiration(Field):
  """An expiration field."""


class FragmentOffset(Field):
  """A fragment-offset field."""


class ForwardingClass(Field):
  """A forwarding-class field."""


class ForwardingClassExcept(Field):
  """A forwarding-class-except field."""


class IcmpCode(Field):
  """A icmp-code field."""


class IcmpType(Field):
  """A icmp-type field."""


class Logging(Field):
  """A logging field."""


class LossPriority(Field):
  """A loss-priority field."""


class Option(Field):
  """An Option field."""


class Owner(Field):
  """An owner field."""


class NextIP(Field):
  """An owner field."""


class PacketLength(Field):
  """A packet-length field."""


class Platform(Field):
  """A platform field."""


class PlatformExclude(Field):
  """A platform-exclude field."""


class Policer(Field):
  """A rate-limit-icmp field."""


class PortMirror(Field):
  """A port-mirror field."""


class Precedence(Field):
  """A precedence field."""


class Protocol(Field):
  """A Protocol field."""


class ProtocolExcept(Field):
  """A protocol-except field."""


class Qos(Field):
  """A rate-limit-icmp field."""


class PANApplication(Field):
  """A rate-limit-icmp field."""


class RoutingInstance(Field):
  """A routing-instance field."""


class SourceAddress(Address):
  """A source-address field."""


class SourceExclude(Address):
  """A source-exclude field."""


class SourceInterface(Field):
  """A source-interface field."""


class SourcePort(Port):
  """A source-port field."""


class SourcePrefix(Field):
  """A source-prefix field."""


class SourcePrefixExcept(Field):
  """A source-prefix-except field."""


class SourceTag(Field):
  """A source tag field."""

class SourceZone(Field):
  """A source-zone field."""

class Target(Field):
  """A target field."""


class Timeout(IntegerField):
  """A timeout field."""


class TrafficType(Field):
  """A traffic-type field."""


class TrafficClassCount(Field):
  """A traffic-class-count field."""


class Verbatim(Field):
  """A verbatim field."""


class Vpn(Field):
  """A vpn field."""


destination_address_fields = (DestinationAddress, DestinationExclude,
                              DestinationPrefix)

field_map = {
    'action': Action,
    'address': Address,
    'comment': Comment,
    'counter': Counter,
    'destination-address': DestinationAddress,
    'destination-exclude': DestinationExclude,
    'destination-interface': DestinationInterface,
    'destination-port': DestinationPort,
    'destination-prefix': DestinationPrefix,
    'destination-prefix-except': DestinationPrefixExcept,
    'destination-tag': DestinationTag,
    'destination-zone': DestinationZone,
    'dscp-match': DscpMatch,
    'dscp-set': DscpSet,
    'ether-type': EtherType,
    'expiration': Expiration,
    'fragment-offset': FragmentOffset,
    'forwarding-class': ForwardingClass,
    'forwarding-class-except': ForwardingClassExcept,
    'icmp-code': IcmpCode,
    'icmp-type': IcmpType,
    'logging': Logging,
    'loss-priority': LossPriority,
    'option': Option,
    'owner': Owner,
    'next-ip': NextIP,
    'packet-length': PacketLength,
    'platform': Platform,
    'platform-exclude': PlatformExclude,
    'policer': Policer,
    'port': Port,
    'port-mirror': PortMirror,
    'precedence': Precedence,
    'protocol': Protocol,
    'protocol-except': ProtocolExcept,
    'qos': Qos,
    'pan-application': PANApplication,
    'routing-instance': RoutingInstance,
    'source-address': SourceAddress,
    'source-exclude': SourceExclude,
    'source-interface': SourceInterface,
    'source-port': SourcePort,
    'source-prefix': SourcePrefix,
    'source-prefix-except': SourcePrefixExcept,
    'source-tag': SourceTag,
    'source-zone': SourceZone,
    'target': Target,
    'timeout': Timeout,
    'traffic-class-count': TrafficClassCount,
    'traffic-type': TrafficType,
    'verbatim': Verbatim,
    'vpn': Vpn,
    'encapsulate': Encapsulate,
    'decapsulate': Decapsulate,
}


class Block:
  """A section containing fields."""

  def __init__(self):
    self.fields = []

  def __iter__(self):
    return iter(self.fields)

  def __getitem__(self, i):
    return self.fields[i]

  def __str__(self):
    buf = []
    buf.append(type(self).__name__.lower())
    buf.append(' ')
    if self.Name():
      buf.append(self.Name())
      buf.append(' ')
    buf.append('{')  # }
    buf.append('\n')
    for field in self.fields:
      buf.append('  ')
      buf.append(str(field))
      buf.append('\n')
    buf.append('}')
    buf.append('\n')
    return ''.join(buf)

  def AddField(self, field):
    if not issubclass(type(field), Field):
      raise TypeError('%s not subclass of Field.' % field)
    self.fields.append(field)

  def FieldsWithType(self, f_type):
    if not issubclass(f_type, Field):
      raise TypeError('%s not subclass of Field.' % f_type)
    return [x for x in self.fields if isinstance(x, f_type)]

  def Match(self, match_fn):
    """Yield the fields and their indices for which match_fn is True."""
    for i, f in enumerate(self.fields):
      if match_fn(f):
        yield i, f

  def Name(self):
    return ''

  def __eq__(self, o):
    if not isinstance(o, self.__class__):
      return False
    if len(self.fields) != len(o.fields):
      return False
    for mine, theirs in zip(self.fields, o.fields):
      logging.debug('testing "%s" vs "%s"', mine, theirs)
      if mine != theirs:
        return False
    return True

  def __ne__(self, o):
    return not self == o


class Header(Block):
  """A header block."""


class Term(Block):
  """A policy term."""

  def __init__(self, name):
    super().__init__()
    self.name = name

  def Name(self):
    return self.name

  def __eq__(self, o):
    if not super().__eq__(o):
      return False
    return self.name == o.name

  def Describe(self):
    """Return a human-readable description of the term."""
    verbatims = self.FieldsWithType(Verbatim)
    if verbatims:
      return 'Verbatim: %s' % verbatims

    handled = set()
    handled.update(self.FieldsWithType(Comment))

    pieces = []
    actions = self.FieldsWithType(Action)
    if len(actions) != 1:
      raise ValueError('No action or multiple actions.')
    handled.update(actions)
    pieces.append(actions[0].value.title() + ' traffic')

    protocols = self.FieldsWithType(Protocol)
    all_protocols = set()
    if protocols:
      handled.update(protocols)
      for protocol in protocols:
        all_protocols.update(protocol.value.split())
      pieces.append('using ' + ' or '.join(sorted(all_protocols)))

    icmp_code = self.FieldsWithType(IcmpCode)
    all_icmp_code = set()
    if icmp_code:
      handled.update(icmp_code)
      for code in icmp_code:
        all_icmp_code.update(code.value.split())
      pieces.append('(ICMP code %s)' % ', '.join(sorted(all_icmp_code)))

    icmp_types = self.FieldsWithType(IcmpType)
    all_icmp_types = set()
    if icmp_types:
      handled.update(icmp_types)
      for icmp_type in icmp_types:
        all_icmp_types.update(icmp_type.value.split())
      pieces.append('(ICMP types %s)' % ', '.join(sorted(all_icmp_types)))

    sources = self.FieldsWithType(SourceAddress)
    if sources:
      handled.update(sources)
      pieces.append('originating from')
      all_sources = set()
      for source in sources:
        all_sources.update(source.value)
      pieces.append(', '.join(sorted(all_sources)))

    source_ports = self.FieldsWithType(SourcePort)
    if source_ports:
      handled.update(source_ports)
      if sources:
        pieces.append('using port')
      else:
        pieces.append('originating port')
      all_sources = set()
      for source in source_ports:
        all_sources.update(source.value)
      pieces.append(', '.join(sorted(all_sources)))

    destinations = self.FieldsWithType(DestinationAddress)
    if destinations:
      handled.update(destinations)
      pieces.append('destined for')
      all_destinations = set()
      for destination in destinations:
        all_destinations.update(destination.value)
      pieces.append(', '.join(sorted(all_destinations)))

    destination_ports = self.FieldsWithType(DestinationPort)
    if destination_ports:
      handled.update(destination_ports)
      if destinations:
        pieces.append('on port')
      else:
        pieces.append('destined for port')
      all_destinations = set()
      for destination in destination_ports:
        all_destinations.update(destination.value)
      pieces.append(', '.join(sorted(all_destinations)))

    vpns = self.FieldsWithType(Vpn)
    if vpns:
      handled.update(vpns)
      pieces.append('via VPNs')
      pieces.append(','.join(x.value for x in vpns))

    # Ignore some fields
    for ignored_type in (Expiration, Owner):
      ignored_fields = self.FieldsWithType(ignored_type)
      if ignored_fields:
        handled.update(ignored_fields)

    for field in self:
      if field not in handled:
        raise ValueError('Uncovered field: ' + str(field))
    return ' '.join(pieces)


class BlankLine:
  """A blank line."""

  def __str__(self):
    return '\n'

  def __eq__(self, o):
    return isinstance(o, self.__class__)

  def __ne__(self, o):
    return not self == o


class CommentLine:
  """A comment in the file."""

  def __init__(self, data):
    self.data = data

  def __str__(self):
    return str(self.data) + '\n'

  def __eq__(self, o):
    if not isinstance(o, self.__class__):
      return False
    return self.data == o.data

  def __ne__(self, o):
    return not self == o


class Include:
  """A reference to another policy definition."""

  def __init__(self, identifier):
    self.identifier = identifier

  def __str__(self):
    return '#include %s' % self.identifier

  def __eq__(self, o):
    if not isinstance(o, self.__class__):
      return False
    return self.identifier == o.identifier

  def __ne__(self, o):
    return not self == o


class Policy:
  """An ordered list of headers, terms, comments, blank lines and includes."""

  def __init__(self, identifier):
    self.identifier = identifier
    self.members = []

  def AddMember(self, member):
    m_type = type(member)
    if (m_type not in (Include, CommentLine, BlankLine)
        and not issubclass(m_type, Block)):
      raise TypeError('%s must be a Block, CommentLine, BlankLine,'
                      ' or Include' % m_type)
    self.members.append(member)

  def __str__(self):
    return ''.join(str(x) for x in self.members)

  def __iter__(self):
    return iter(self.members)

  def __getitem__(self, i):
    return self.members[i]

  def Match(self, match_fn):
    """Yield the members and their indices for which match_fn is True."""
    for i, m in enumerate(self.members):
      if match_fn(m):
        yield i, m

  def MatchFields(self, block_match_fn, field_match_fn):
    for match_idx, m in self.Match(block_match_fn):
      if not isinstance(m, Block):
        continue
      for field_idx, f in m.Match(field_match_fn):
        yield match_idx, field_idx, f


class PolicyParser:
  """Parse a policy object from a data buffer."""

  def __init__(self, data, identifier):
    self.data = data
    self.identifier = identifier
    self.block_in_progress = None
    self.policy = None

  def Parse(self):
    """Do the needful."""
    self.policy = Policy(self.identifier)
    for line in self.data.split('\n'):
      line = line.strip()
      logging.debug('Processing line: "%s"', line)
      if self.block_in_progress:
        self.ParseInBlock(line)
      else:
        self.ParseTopLevel(line)
    if self.block_in_progress:
      raise ValueError('Unexpected EOF reading "%s"' % self.block_in_progress)
    return self.policy

  def ParseTopLevel(self, line):
    """Parse a line not nested within a block."""
    if line == '':  # pylint: disable=g-explicit-bool-comparison
      self.policy.AddMember(BlankLine())
      return
    if line.startswith('#'):
      if line.startswith('#include '):
        self.ParseIncludeLine(line)
        return
      self.ParseCommentLine(line)
      return
    if line.startswith('header {') or line.startswith('header{'):  # }
      self.ParseHeaderLine(line)
      return
    if line.startswith('term '):
      self.ParseTermLine(line)
      return
    raise ValueError('Unhandled top-level line %s' % line)

  def ParseCommentLine(self, line):
    """Parse a line with a line level comment."""
    if self.block_in_progress:
      raise ValueError('Found comment line in block: %s' % line)
    self.policy.AddMember(CommentLine(line))

  def ParseIncludeLine(self, line):
    """Parse an #include line refering to another file."""
    if self.block_in_progress:
      raise ValueError('Found include line in block: %s' % line)
    line_parts = line.split()
    if len(line_parts) < 2:
      raise ValueError('Invalid include: %s' % line)
    inc_ref = line_parts[1]
    if '#' in inc_ref:
      inc_ref, _ = inc_ref.split('#', 1)
    self.policy.AddMember(Include(inc_ref))

  def ParseHeaderLine(self, line):
    """Parse a line beginning a header block."""
    if self.block_in_progress:
      raise ValueError('Nested blocks not allowed: %s' % line)
    self.block_in_progress = Header()

  def ParseTermLine(self, line):
    """Parse a line beginning a term block."""
    if self.block_in_progress:
      raise ValueError('Nested blocks not allowed: %s' % line)
    line_parts = line.split()

    # Some terms don't have a space after the name
    if '{' in line_parts[1]:  # }
      brace_idx = line_parts[1].index('{')  # }
      line_parts[1] = line_parts[1][:brace_idx]
    else:
      if not line_parts[2].startswith('{'):  # }
        raise ValueError('Invalid term line: %s' % line)
    term_name = line_parts[1]
    self.block_in_progress = Term(term_name)

  def ParseInBlock(self, line):
    """Parse a line when inside a block definition."""
    if line == '' or line.startswith('#'):  # pylint: disable=g-explicit-bool-comparison
      return
    if '::' in line:
      self.ParseField(line)
      return
    if line.startswith('}'):
      self.policy.AddMember(self.block_in_progress)
      self.block_in_progress = None
      return
    if self.block_in_progress is not None:
      self.block_in_progress.fields[-1].Append('\n' + line)

  def ParseField(self, line):
    """Parse a line containing a block field."""
    name, value = line.split('::', 1)
    name = name.strip().lower()
    f_type = field_map.get(name)
    if not f_type:
      raise ValueError('Invalid field line: %s' % line)
    self.block_in_progress.AddField(f_type(value))
