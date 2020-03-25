# Lint as: python3
"""Generic Google Cloud Platform multi-product generator.

Base class for GCP firewalling products.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import json
from capirca.lib import aclgenerator

import six


class Error(Exception):
  """Generic error class."""


class TermError(Error):
  """Raised when a term is not valid."""


class HeaderError(Error):
  """Raised when a header is not valid."""


class Term(aclgenerator.Term):
  """A Term object."""

  def _TruncateComment(self, max_length):
    """Truncate comment."""
    raw_comment = ' '.join(self.term.comment)
    if len(raw_comment) > max_length:
      return raw_comment[:max_length]
    return raw_comment


class GCP(aclgenerator.ACLGenerator):
  """A GCP object."""

  _GOOD_DIRECTION = ['INGRESS', 'EGRESS']

  def __str__(self):
    """Return the JSON blob for a GCP object."""
    out = '%s\n\n' % (
        json.dumps(self.hf_policies, indent=2,
                   separators=(six.ensure_str(','), six.ensure_str(': ')),
                   sort_keys=True))
    return out


def IsDefaultDeny(term):
  """Return true if a term is a default deny without IPs, ports, etc."""
  skip_attrs = ['flattened', 'flattened_addr', 'flattened_saddr',
                'flattened_daddr', 'action', 'comment', 'name']
  if 'deny' not in term.action:
    return False
  # This lc will look through all methods and attributes of the object.
  # It returns only the attributes that need to be looked at to determine if
  # this is a default deny.
  for i in [a for a in dir(term) if not a.startswith('__') and
            a.islower() and not callable(getattr(term, a))]:
    if i in skip_attrs:
      continue
    v = getattr(term, i)
    if isinstance(v, str) and v:
      return False
    if isinstance(v, list) and v:
      return False

  return True
