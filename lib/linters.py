# Copyright 2008 Google Inc. All Rights Reserved.
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from collections import namedtuple, defaultdict
from copy import deepcopy
import datetime
import json
import re

from lib import nacaddr
import yaml

Error = namedtuple('Error', ['filename', 'lineno', 'offset', 'Severity',
                             'message', 'category'])


def sanitizeNetworkItem(x):
  # Remove comments and identify just the content we care about
  return x.split('#', 1)[0].strip()


class Severity(object):
  """Helper class to represent the severity of a lint problem.

  Methods:
    human(k) - represents the human-legible value
    int(k) - represents a numerical representation of how bad the error is,
             mimicing the same values used for Phabricator.
  """

  DISABLED = 'disabled'
  ADVICE = 'advice'
  WARNING = 'warning'
  AUTOFIX = 'autofix'
  ERROR = 'error'

  @classmethod
  def human(cls, k):
    mapping = {
        cls.DISABLED: 'Disabled',
        cls.ADVICE: 'Advice',
        cls.WARNING: 'Warning',
        cls.ERROR: 'Error',
        cls.AUTOFIX: 'Auto-Fix',
    }
    return mapping[k]

  @classmethod
  def int(cls, k):
    mapping = {
        cls.DISABLED: 10,
        cls.ADVICE: 20,
        cls.WARNING: 30,
        cls.ERROR: 40,
        cls.AUTOFIX: 25,
    }
    return mapping[k]


class LintErrors(object):
  """Storage class for tracking what lint errors have been observed."""

  def __init__(self):
    self.errs = []
    self.filename = None

  def __iter__(self):
    for e in self.errs:
      yield e

  def add(self, severity_code, msg, lineno=0, offset=0, filename=None,
      category='CAP'):
    """Construct a lint error based off the given location provided"""
    fn = filename or self.filename or 'unknown'
    self.errs.append(Error(fn, lineno, offset, severity_code, msg, category))

  def tree(self, sort=True):
    """Return a tree representation of the stored lint errors"""
    t = defaultdict(list)
    for e in self.errs:
      t[e.filename].append(e)
    if sort:
      for v in t.values():
        v.sort(key=lambda e: e.lineno)
    return t

  def pprint(self):
    """Output a pretty-print of the stored lint errors"""
    for filename, errors in self.tree().iteritems():
      print("%s -" % filename)
      for error in errors:
        print("  %5d <%s> %s" % (error.lineno,
                     Severity.human(error.Severity),
                     error.message))

  def plain(self):
    """Do a plain print() of the stored lint errors"""
    for error in sorted(self.errs, key=lambda x: (x.filename, x.lineno)):
      print(error)

  def json(self):
    """Print a json representation of the tree structure"""
    print(json.dumps(self.tree()))


def register_linter(f):
  """Class decorator to register a linter to be executed."""
  globals().setdefault('CAPIRCA_LINTERS', []).append(f)
  return f


def get_linters():
  """Get all the globally registered linters"""
  return globals().get('CAPIRCA_LINTERS', [])


def build_linters(configpath):
  """Helper function to construct a LintErrors and all linters"""
  errors = LintErrors()
  if configpath:
    with open(configpath) as f:
      config = yaml.load(f.read())
  else:
    config = {}
  linters = [kls(errors=errors, config=config) for kls in get_linters()]
  return (errors, linters)


class BaseLintRule(object):
  """Base Lint Rule class. All lint rules should extend this.

  All configurable parameters should be placed into DEFAULTS - as these
  values get merged with the optional user-specified YAML file.

  setup() can be implemented by child classes that might need to do
  additional configuration such as remote data-fetching.
  """

  CONFIG_NAME = None
  DEFAULT_ENABLED = True
  CATEGORY = None
  DEFAULTS = {}

  def __init__(self, errors, config):
    self.global_config = config
    self.errors = errors
    # build a local copy of the linter specific config
    cn = self.CONFIG_NAME or self.__class__.__name__
    local_config = deepcopy(self.DEFAULTS)
    local_config.update(self.global_config.get(cn, {}))
    self.config = local_config
    self.setup()

  def setup(self):
    """setup() may optionally be implemented by each linter"""
    pass

  def add(self, *args, **kwargs):
    if 'category' not in kwargs and self.CATEGORY:
      kwargs['category'] = self.CATEGORY
    self.errors.add(*args, **kwargs)

  def lint_naming(self, definitions):
    """Execute the lint check_* methods against the specified definitions."""
    if not self.config.get('enabled', self.DEFAULT_ENABLED):
      return

    for itemunit in definitions.networks.values():
      self.check_network(itemunit)

    for itemunit in definitions.services.values():
      self.check_service(itemunit)

    self.check_networks(definitions.networks)
    self.check_services(definitions.services)

  def lint_policy(self, policy):
    """Execute the lint check_term method against the specified policy"""
    if not self.config.get('enabled', self.DEFAULT_ENABLED):
      return

    for header, terms in policy.filters:
      if not terms:
        # no terms included -probably just include statements
        continue
      for term in terms:
        self.check_term(policy.filename, header, term)

  def check_network(self, network):
    """May be implemented to check a given network found in a .net file"""
    pass

  def check_service(self, service):
    """May be implemented to check a given service found in a .svc file"""
    pass

  def check_networks(self, networks):
    """May be implemented to check all of the networks found in a .net file"""
    pass

  def check_services(self, services):
    """May be implemented to check all of the services found in a .svc file"""
    pass

  def check_term(self, policy, header, term):
    """May be implemented to check the given term under a given header"""
    pass


@register_linter
class AddressNumEnforce(BaseLintRule):
  """Warns about terms with more than a few address tokens."""

  def check_term(self, policy, header, term):
    addr_attrs = (
      'source_address',
      'destination_address',
      'destination_address_exclude',
      'source_address_exclude',
    )
    for attrname in addr_attrs:
      addrs = getattr(term, attrname)
      parents = set([addr.parent_token for addr in addrs])
      if len(parents) > 4:
        msg = ("term %s has too many objects in" % term.name +
             " one of the address fields. " +
             "Please review and consolidate the addresses")
        self.add(Severity.WARNING, msg, term.name.lineno)


@register_linter
class RegexNameEnforcer(BaseLintRule):
  """Ensures objects and terms following naming conventions."""

  DEFAULTS = {
    'NETNAME': r'^([A-Z][A-Z0-9_]+|h_[0-9a-f\.]+|n_[0-9a-f\.]+_[0-9]+)$',
    'SVCNAME': r'^((TCP|UDP|TCP_UDP)_[0-9]+(-[0-9]+)?|[A-Z][A-Z0-9_]+)$',
    'TERMNAME': {
      'default': r'^[a-z][a-z0-9\-\.]+$',
      'srx': r'^[a-z][a-z0-9\-]+$',
    }
  }

  def setup(self):
    self.netname_re = re.compile(self.config['NETNAME'])
    self.svcname_re = re.compile(self.config['SVCNAME'])
    self.termname_re = {k: re.compile(v) for k, v
              in self.DEFAULTS['TERMNAME'].items()}

  def check_network(self, network):
    if not self.netname_re.match(network.name):
      msg = '%s is not a valid network name' % network.name
      self.add(Severity.WARNING, msg, network.name.lineno)

  def check_service(self, service):
    if not self.svcname_re.match(service.name):
      msg = '%s is not a valid service name' % service.name
      self.add(Severity.WARNING, msg, service.name.lineno)

  def check_term(self, policy, header, term):
    header_targets = {}
    if header:
      header_targets = {x.platform for x in header.target}
    for target, re_pattern in self.termname_re.iteritems():
      if target == 'default' and not re_pattern.match(term.name):
        msg = ('%s is not a valid '
             'term name for all platforms' % term.name)
        self.add(Severity.ERROR, msg, term.name.lineno)
      elif target in header_targets and not re_pattern.match(term.name):
        msg = '%s is not a valid term name for target: %s' % (term.name,
                                    target)
        self.add(Severity.ERROR, msg, term.name.lineno)


@register_linter
class BoilerplateTermEnforcer(BaseLintRule):
  """Enforces files with BOILERPLATE in the name must have all terms
  prefixed with "bp-"
  """

  def check_term(self, policy, header, term):
    if header:
      return
    if not term.name.startswith('bp-') and 'BOILERPLATE' in policy:
      msg = ("Term %s is in a boilerplate, and should start with "
           "'bp-'" % term.name)
      self.add(Severity.WARNING, msg, term.name.lineno)


@register_linter
class Inet6TermEnforcer(BaseLintRule):

  """Enforces that if this is a file handling inet6, that all of the terms
  must end with -v6."""

  def check_term(self, policy, header, term):
    if not header:
      return
    header_options = set()
    for target in header.target:
      header_options |= set(target.options)
    if 'inet6' in header_options and not term.name.endswith('-v6'):
      msg = ("Term %s is in an inet6 policy, and should end with "
           "'-v6'" % term.name)
      self.add(Severity.WARNING, msg, term.name.lineno)


@register_linter
class SinglePortEnforcer(BaseLintRule):

  """ Ensures service objects are defined according to the name. """

  def check_service(self, service):
    name = service.name
    if name.startswith('TCP_UDP_'):
      if len(service.items) == 2:
        return
      msg = '%s should contain two port specifications' % name
      self.add(Severity.WARNING, msg, name.lineno)
    elif (name.startswith('TCP_') or name.startswith('UDP_')) \
        and len(service.items) != 1:
      msg = '%s should contain a single port specification' % name
      self.add(Severity.WARNING, msg, name.lineno)


@register_linter
class SameLineDefinitionsEnforcer(BaseLintRule):

  """ Ensures the names of objects are not seen more than once. """

  def check_service(self, service):
    seen_lines = set()
    for item in service.items:
      if item.lineno in seen_lines:
        msg = 'Services on same line'
        self.add(Severity.WARNING, msg, lineno=item.lineno)
      seen_lines.add(item.lineno)

  def check_network(self, network):
    seen_lines = set()
    for item in network.items:
      if item.lineno in seen_lines:
        msg = 'Networks on same line'
        self.add(Severity.WARNING, msg, lineno=item.lineno)
      seen_lines.add(item.lineno)


@register_linter
class CharLengthEnforcer(BaseLintRule):

  """ Ensures the names of objects or terms are under the maximum length. """

  DEFAULTS = {
    'MAX_TERM_LENS': {
      'panfw': 31,
      'juniper': 63,
      'srx': 63,
    },
    'MAX_NETWORK_LEN': 63,
    'MAX_SERVICE_LEN': 63,
  }

  def check_term(self, policy, header, term):
    # For includes, which don't have a header, assume the lowest term
    # length, as it could be included in a policy with any target
    if not header:
      max_len = min(self.config['MAX_TERM_LENS'].values())
      if len(term.name) > max_len:
        msg = ("Term %s is longer than %d characters" %
             (term.name, max_len))
        self.add(Severity.WARNING, msg, lineno=term.name.lineno)
    # for policy files, which have headers, only check for the appropriate
    # target
    else:
      header_targets = {x.platform for x in header.target}
      for target, max_len in self.config['MAX_TERM_LENS'].items():
        if target in header_targets and len(term.name) > max_len:
          msg = ("Term %s is longer than %d characters" %
               (term.name, max_len))
          self.add(Severity.WARNING, msg, lineno=term.name.lineno)

  def check_network(self, network):
    max_len = self.config['MAX_NETWORK_LEN']
    if len(network.name) > max_len:
      msg = 'Network name %s is more than %d characters' % (network.name,
                                  max_len)
      self.add(Severity.WARNING, msg, network.name.lineno)

  def check_service(self, service):
    max_len = self.config['MAX_SERVICE_LEN']
    if len(service.name) > max_len:
      msg = 'Service name %s is more than %d characters' % (service.name,
                                  max_len)
      self.add(Severity.WARNING, msg, service.name.lineno)


@register_linter
class ExpiredTermEnforcer(BaseLintRule):

  """ Notifies about terms that are expired or expiring soon. """

  DEFAULTS = {
    'WARN_DAYS': 14,
    'ADVICE_DAYS': 30,
    'ERROR_DAYS': 0,
  }

  def check_term(self, policy, header, term):
    if term.expiration:
      sev = None
      days = (term.expiration - datetime.date.today()).days
      if days < self.config['ERROR_DAYS']:
        sev = Severity.ERROR
      elif days < self.config['WARN_DAYS']:
        sev = Severity.WARNING
      elif days < self.config['ADVICE_DAYS']:
        sev = Severity.ADVICE
      if sev is not None:
        if days < 0:
          msg = 'term is expired!'
        else:
          msg = '%d days until term expiration' % days
        self.add(sev, msg, lineno=term.name.lineno)


@register_linter
class EmptyNetworkOrPorts(BaseLintRule):

  """ Ensures network and service objects have an element within them. """

  def check_service(self, service):
    if not len(service.items):
      msg = 'Services must contain at least one element'
      self.add(Severity.ERROR, msg, lineno=service.name.lineno)

  def check_network(self, network):
    if not len(network.items):
      msg = 'Networks must contain at least one element'
      self.add(Severity.ERROR, msg, lineno=network.name.lineno)


@register_linter
class CheckValidNetwork(BaseLintRule):

  """ Ensures network IP addresses are accurate and in the proper format,
  and looks for eggregiously large IPv6 subnets."""

  DEFAULTS = {
    'IP_RE': r'[0-9a-f:\.]+(/[0-9]{1,3})?',
    'CIDR_RE': r'(/[0-9]{1,3})',
    'V6_WHITELIST': [
      "::/8",
      "100::/8",
      "200::/7",
      "400::/6",
      "800::/5",
      "1000::/4",
      "4000::/3",
      "6000::/3",
      "8000::/3",
      "a000::/3",
      "c000::/3",
      "e000::/4",
      "f000::/5",
      "f800::/6",
      "fe00::/9",
      "fec0::/10",
    ],
  }

  def check_network(self, network):
    regex = re.compile(self.config['IP_RE'])
    cidr_regex = re.compile(self.config['CIDR_RE'])
    for item in network.items:
      stripped = sanitizeNetworkItem(item)
      if not regex.match(stripped):
        continue

      try:
        network = nacaddr.IP(stripped)
      except ValueError:
        msg = '%s is not a valid network' % stripped
        self.add(Severity.ERROR, msg, lineno=item.lineno)
      else:
        # ensure there the entry is in CIDR notation
        if not cidr_regex.search(stripped):
          msg = ('%s is not in CIDR notation (must have a /## '
               "network assignment)") % stripped
          self.add(Severity.ERROR, msg, lineno=item.lineno)
          # skip the other two checks because they require a network
          continue
        # Warn for extraordinarily large v6 subnets (usually a mistake
        # from copying a v4 subnet)
        if (network.prefixlen < 33 and network.version == 6 and
            network.with_prefixlen.lower() not in
            self.config['V6_WHITELIST']):
          msg = ("%s is an extremely large network and may be an error. "
                 "Please confirm this is the correct CIDR mask." %
                 network.with_prefixlen)
          self.add(Severity.WARNING, msg, lineno=item.lineno)
        # check that the IP they are defining is the network address
        try:
          # need the raw_ip without the subnet for comparing with the
          # network address
          raw_ip = str(nacaddr.IP(stripped.split("/")[0]).ip).lower()
        except IndexError:
          pass
        else:
          if raw_ip != str(network.network).lower():
            msg = ("%s is not the network address for this "
                 "network: %s/%s" % (raw_ip,
                           str(network.network).lower(),
                           network.prefixlen))
            self.add(Severity.ERROR, msg, lineno=item.lineno)


@register_linter
class NetworkMatcher(BaseLintRule):

  """ Network name enforcement. Also ensures a given network name matches the
    network specified. """

  DEFAULTS = {
    'NETNAME': r'^(h_[0-9a-f\.]+|n_[0-9a-f\.]+_[0-9]+)$',
    'FUZZ_IPV6': True,
  }

  def check_network(self, network):
    regex = re.compile(self.config['NETNAME'])
    if not regex.match(network.name):
      return
    n = network.name.lstrip('hn_')
    n = n.replace('_', '/')
    if n.count('.') != 3:
      # ipv6 address... we hope. fuzzit.
      n = n.replace('.', ':')
      if (n.find('::') < 0 and n.count(':') != 7 and
          self.config['FUZZ_IPV6']):
        # incomplete ipv6 - doubletap.
        n = n + '::'
    try:
      net_ip = nacaddr.IP(n)
    except ValueError:
      msg = '%s (%s) is not a valid network' % (network.name, n)
      self.add(Severity.ERROR, msg, lineno=network.name.lineno)
      return

    for item in network.items:
      sanitized = sanitizeNetworkItem(item)
      try:
        item_ip = nacaddr.IP(sanitized)
      except ValueError:
        # invalid network element - not our problem
        continue
      if net_ip != item_ip:
        msg = ('%s does not match name specification of %s'
             % (item_ip, net_ip))
        self.add(Severity.WARNING, msg, lineno=item.lineno)


@register_linter
class IndentEnforcer(BaseLintRule):

  """ Ensures proper amount of indentation is present. """

  DEFAULTS = {
    'INDENT': 4,
    'MIN_ELEMENTS': 2,
  }

  def check_network(self, network):
    indent = self.config['INDENT']
    if len(network.items) < self.config['MIN_ELEMENTS']:
      return
    for item in network.items:
      if item.offset == indent:
        continue
      msg = '%s indented by %d, not %d' % (item, item.offset, indent)
      self.add(Severity.WARNING, msg, lineno=item.lineno)

  def check_service(self, service):
    indent = self.config['INDENT']
    if len(service.items) < self.config['MIN_ELEMENTS']:
      return
    for item in service.items:
      if item.offset == indent:
        continue
      msg = '%s indented by %d, not %d' % (item, item.offset, indent)
      self.add(Severity.WARNING, msg, lineno=item.lineno)


@register_linter
class CounterEnforcer(BaseLintRule):

  """ Ensures terms in a policy with a given target have a counter """

  DEFAULTS = {
    'TARGETS': ['juniper'],
  }

  def check_term(self, policy, header, term):
    # a header (with target(s) is required for this check, so skip it on
    # include files
    if not header:
      return
    header_targets = {x.platform for x in header.target}
    for target in self.config['TARGETS']:
      if target in header_targets and not term.counter:
        msg = ('A counter is required for term %s, it\'s in a '
               'policy with a "%s" target' % (term.name, target))
        self.add(Severity.WARNING, msg, lineno=term.name.lineno)
