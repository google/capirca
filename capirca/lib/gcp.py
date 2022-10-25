"""Generic Google Cloud Platform multi-product generator.

Base class for GCP firewalling products.
"""

import ipaddress
import json
import re

from capirca.lib import aclgenerator

import six


class Error(Exception):
  """Generic error class."""


class TermError(Error):
  """Raised when a term is not valid."""


class HeaderError(Error):
  """Raised when a header is not valid."""


class UnsupportedFilterTypeError(Error):
  """Raised when an unsupported filter type is specified."""


class Term(aclgenerator.Term):
  """A Term object."""

  # Protocols allowed by name from:
  # https://cloud.google.com/vpc/docs/firewalls#protocols_and_ports
  # 'all' is needed for the dedault deny, it should not be used in a pol file.
  _ALLOW_PROTO_NAME = frozenset(
      ['tcp', 'udp', 'icmp', 'esp', 'ah', 'ipip', 'sctp', 'all'])

  def _GetPorts(self):
    """Return a port or port range in string format."""
    ports = []
    for start, end in self.term.destination_port:
      if start == end:
        ports.append(str(start))
      else:
        ports.append('%d-%d' % (start, end))
    return ports

  def _GetLoggingSetting(self):
    """Return true if a term indicates that logging is desired."""
    # Supported values in GCP are '', 'true', and 'True'.
    settings = [str(x) for x in self.term.logging]
    if any(value in settings for value in ['true', 'True']):
      return True
    return False


class GCP(aclgenerator.ACLGenerator):
  """A GCP object."""

  policies = []
  _GOOD_DIRECTION = ['INGRESS', 'EGRESS']

  def __str__(self):
    """Return the JSON blob for a GCP object."""
    out = '%s\n\n' % (
        json.dumps(
            self.policies,
            indent=2,
            separators=(six.ensure_str(','), six.ensure_str(': ')),
            sort_keys=True))
    return out


def IsDefaultDeny(term):
  """Return true if a term is a default deny without IPs, ports, etc."""
  skip_attrs = [
      'flattened', 'flattened_addr', 'flattened_saddr', 'flattened_daddr',
      'action', 'comment', 'name', 'logging'
  ]
  if 'deny' not in term.action:
    return False
  # This lc will look through all methods and attributes of the object.
  # It returns only the attributes that need to be looked at to determine if
  # this is a default deny.
  for i in [
      a for a in dir(term) if not a.startswith('__') and a.islower() and
      not callable(getattr(term, a))
  ]:
    if i in skip_attrs:
      continue
    v = getattr(term, i)
    if isinstance(v, str) and v:
      return False
    if isinstance(v, list) and v:
      return False

  return True


def IsProjectIDValid(project):
  """Return true if a project ID is valid.

  https://cloud.google.com/resource-manager/reference/rest/v1/projects

  "It must be 6 to 30 lowercase letters, digits, or hyphens. It must start with
  a letter. Trailing hyphens are prohibited."

  Args:
    project: A string.

  Returns:
    bool: True if a project ID matches the pattern and length requirements.
  """
  if len(project) < 6 or len(project) > 30:
    return False
  return bool(re.match('^[a-z][a-z0-9\\-]*[a-z0-9]$', project))


def IsVPCNameValid(vpc):
  """Return true if a VPC name is valid.

  https://cloud.google.com/compute/docs/reference/rest/v1/networks

  "The first character must be a lowercase letter, and all following characters
  (except for the last character) must be a dash, lowercase letter, or digit.
  The last character must be a lowercase letter or digit."

  Args:
    vpc: A string.

  Returns:
    bool: True if a VPC name matches the pattern and length requirements.
  """
  if len(vpc) < 1 or len(vpc) > 63:
    return False
  return bool(re.match('^[a-z]$|^[a-z][a-z0-9-]*[a-z0-9]$', vpc))


def TruncateString(raw_string, max_length):
  """Returns truncated raw_string based on max length.

  Args:
    raw_string: String to be truncated.
    max_length: max length of string.

  Returns:
    string: The truncated string.
  """
  if len(raw_string) > max_length:
    return raw_string[:max_length]
  return raw_string


def GetIpv6TermName(term_name):
  """Returns the equivalent term name for IPv6 terms.

  Args:
    term_name: A string.

  Returns:
    string: The IPv6 requivalent term name.
  """

  return '%s-%s' % (term_name, 'v6')


def FilterIPv4InIPv6FormatAddrs(addrs):
  """Returns addresses of the appropriate Address Family.

  Args:
    addrs: list of IP addresses.

  Returns:
    list of filtered IPs with no IPv4 in IPv6 format addresses.
  """
  filtered = []
  for addr in addrs:
    ipaddr = ipaddress.ip_interface(addr).ip
    if isinstance(ipaddr, ipaddress.IPv6Address):
      ipv6 = ipaddress.IPv6Address(ipaddr)
      # Check if it's an IPv4-mapped or 6to4 address.
      if ipv6.ipv4_mapped is not None or ipv6.sixtofour is not None:
        continue
      # Check if it's an IPv4-compatible address.
      if ipv6.packed.hex(
      )[:24] == '000000000000000000000000' and not ipv6.is_unspecified:
        continue
    filtered += [addr]
  return filtered
