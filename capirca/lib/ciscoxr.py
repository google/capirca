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

"""Cisco IOS-XR filter renderer."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capirca.lib import cisco


class CiscoXR(cisco.Cisco):
  """A cisco policy object."""

  _PLATFORM = 'ciscoxr'
  _DEFAULT_PROTOCOL = 'ip'
  SUFFIX = '.xacl'
  _PROTO_INT = False

  def _AppendTargetByFilterType(self, filter_name, filter_type):
    """Takes in the filter name and type and appends headers.

    Args:
      filter_name: Name of the current filter
      filter_type: Type of current filter

    Returns:
      list of strings
    """
    target = []
    if filter_type == 'inet6':
      target.append('no ipv6 access-list %s' % filter_name)
      target.append('ipv6 access-list %s' % filter_name)
    else:
      target.append('no ipv4 access-list %s' % filter_name)
      target.append('ipv4 access-list %s' % filter_name)
    return target

  def _GetObjectGroupTerm(self, term, filter_name):
    """Returns an ObjectGroupTerm object."""
    return CiscoXRObjectGroupTerm(term, filter_name)


class CiscoXRObjectGroupTerm(cisco.ObjectGroupTerm):
  ALLOWED_PROTO_STRINGS = cisco.Term.ALLOWED_PROTO_STRINGS + ['pcp', 'esp']
